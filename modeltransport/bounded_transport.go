package modeltransport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (t *Transport) policyRoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(req.Context(), modelTimeout)
	retainContext := false
	defer func() {
		if !retainContext {
			cancel()
		}
	}()
	body, hash, stream, structured, err := t.policy.prepare(req)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	id, err := t.policy.reserve(hash)
	if err != nil {
		return nil, err
	}
	fail := func(outcome string, cause error) (*http.Response, error) {
		if err := t.policy.change(id, outcome, tokenUsage{}); err != nil {
			return nil, err
		}
		return nil, cause
	}
	token, err := t.accessToken(ctx)
	if err != nil {
		return fail("failed", err)
	}
	if err = ctx.Err(); err != nil {
		return fail("failed", err)
	}
	clone := req.Clone(ctx)
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.ContentLength = int64(len(body))
	// There must be no replayable body function or caller framing override.
	clone.GetBody = nil
	clone.TransferEncoding = nil
	clone.Trailer = nil
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}
	for name := range clone.Header {
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "api-key") || strings.EqualFold(name, "x-api-key") || strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Transfer-Encoding") || strings.EqualFold(name, "Idempotency-Key") || strings.EqualFold(name, "X-Idempotency-Key") {
			delete(clone.Header, name)
		}
	}
	clone.Header.Set("Content-Type", "application/json")
	clone.Header.Set("Authorization", "Bearer "+token.Token)
	// Commit the dispatch transition before the first byte of any possible POST.
	// If this commit is ambiguous no network happens and the prior reservation
	// remains a durable stop. Neither credentials nor transport errors are retried.
	if err = t.policy.dispatch(id); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return fail("unknown", err)
	}
	resp, err := t.base.RoundTrip(clone)
	if err != nil {
		return fail("unknown", safeError(ctx, "modeltransport: request failed"))
	}
	if resp.Body == nil {
		return fail("unknown", errors.New("modeltransport: missing response body"))
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return fail("failed", fmt.Errorf("modeltransport: provider returned HTTP %d", resp.StatusCode))
	}
	resp.Body = newAccountingBody(resp.Body, ctx, cancel, t.policy, id, stream, structured)
	retainContext = true
	return resp, nil
}
