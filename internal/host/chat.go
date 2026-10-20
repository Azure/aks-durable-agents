package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/model/openai"
)

type chatFormatKey struct{}

// Preserve the original request's journal input hash while consuming host hints
// before the Chat adapter, which refuses Params. Carry the schema privately to
// HTTP; token/temperature hints cannot override the reasoning-model policy.
func chatRequestContext(ctx context.Context, r api.ModelRequest) (context.Context, api.ModelRequest, error) {
	for name, value := range r.Params {
		switch name {
		case "max_tokens":
			if value == "700" || value == "16384" {
				continue
			}
		case "temperature":
			if value == "0.2" {
				continue
			}
		case "response_format":
			if value != "" && len(value) <= 16384 && json.Valid([]byte(value)) {
				continue
			}
		}
		return nil, api.ModelRequest{}, errors.New("host: unsupported model parameters")
	}
	ctx = context.WithValue(ctx, chatFormatKey{}, r.Params["response_format"])
	// Clear only the provider-facing copy, never the harness-owned parameter map.
	r.Params = nil
	return ctx, r, nil
}

func newChatModel(c Config, p *modeltransport.Policy, credential azcore.TokenCredential) (*openai.Client, error) {
	client, err := modeltransport.NewClient(modeltransport.Config{Endpoint: c.ModelEndpoint, Deployment: c.Deployment, Scope: c.ModelScope, Credential: credential, Transport: c.ModelTransport, Policy: p})
	if err != nil {
		return nil, err
	}
	client.Transport = chatTransport{next: client.Transport, bounded: p != nil}
	return openai.New(openai.WithBaseURL(c.ModelEndpoint), openai.WithModel(c.Deployment), openai.WithHTTPClient(client))
}

type chatTransport struct {
	next    http.RoundTripper
	bounded bool
}

func (t chatTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	format, _ := req.Context().Value(chatFormatKey{}).(string)
	if format == "" {
		return t.next.RoundTrip(req)
	}
	defer req.Body.Close()
	if !t.bounded {
		return nil, errors.New("host: structured output requires bounded policy")
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, 64*1024+1))
	if err != nil || len(data) > 64*1024 {
		return nil, errors.New("host: structured request too large or unreadable")
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(data, &body) != nil || body == nil {
		return nil, errors.New("host: invalid Chat request")
	}
	body["response_format"] = json.RawMessage(format)
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, errors.New("host: cannot encode structured request")
	}
	clone := req.Clone(req.Context())
	clone.Body = io.NopCloser(bytes.NewReader(encoded))
	clone.ContentLength = int64(len(encoded))
	clone.GetBody = nil
	return t.next.RoundTrip(clone)
}
