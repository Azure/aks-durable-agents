package githubtools

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrGitHubInput    = errors.New("invalid GitHub client request")
	ErrGitHubAccess   = errors.New("GitHub App access unavailable")
	ErrGitHubRead     = errors.New("GitHub issue read unavailable")
	ErrGitHubRejected = errors.New("GitHub comment rejected")
	errGitHubHTTP     = errors.New("GitHub HTTP response unavailable")
)

const githubBodyLimit = 1 << 20

// GitHubAccount is fixed operator configuration, never a per-tool destination.
type GitHubAccount struct{ AppID, InstallationID, RepositoryID, Owner, Repository string }
type ClientConfig struct {
	Account        GitHubAccount
	PrivateKeyFile string
}

type Client struct {
	account GitHubAccount
	key     *rsa.PrivateKey
	http    *http.Client
	now     func() time.Time
}

// Access carries only a short-lived installation capability. It cannot mint or
// refresh tokens: it retains neither the signing key nor a Client reference.
// This is not a native approval; the host must bind it to exact call evidence.
type Access struct {
	account           GitHubAccount
	http              *http.Client
	token, permission string
	expiresAt         time.Time
	now               func() time.Time
}

func (Client) String() string            { return "GitHub App client (credentials redacted)" }
func (c Client) GoString() string        { return c.String() }
func (Access) String() string            { return "GitHub installation access (token redacted)" }
func (a Access) GoString() string        { return a.String() }
func (a *Access) Account() GitHubAccount { return a.account }
func (a *Access) ExpiresAt() time.Time   { return a.expiresAt }

// NewClient loads the operator's RSA PEM key without making any network call.
// Errors never include the key, file path or parser diagnostic. Kubernetes
// Secret projections may be symlinks; their packaging is the operator's concern.
func NewClient(c ClientConfig) (*Client, error) { return newClient(c, nil, time.Now) }
func newClient(c ClientConfig, base *http.Transport, now func() time.Time) (*Client, error) {
	a := c.Account
	segment := func(s string) bool { return textOK(s, 256) && s != "." && s != ".." && !strings.ContainsAny(s, "/\\") }
	if !decimalID(a.AppID) || !decimalID(a.InstallationID) || !decimalID(a.RepositoryID) || !segment(a.Owner) || !segment(a.Repository) {
		return nil, ErrGitHubInput
	}
	f, err := os.Open(c.PrivateKeyFile)
	if err != nil {
		return nil, ErrGitHubAccess
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	closeErr := f.Close()
	if err != nil || closeErr != nil || len(raw) > 64<<10 {
		return nil, ErrGitHubAccess
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(raw)
	if err != nil {
		return nil, ErrGitHubAccess
	}
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	base = base.Clone()
	// Match modeltransport's no-replay boundary. Fresh HTTP/1 connections avoid
	// reused-connection and HTTP/2 transport retry paths for non-idempotent POSTs.
	base.DisableKeepAlives = true
	if base.TLSClientConfig != nil {
		base.TLSClientConfig = base.TLSClientConfig.Clone()
		base.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}
	base.Protocols = new(http.Protocols)
	base.Protocols.SetHTTP1(true)
	client := &http.Client{Transport: base, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{account: a, key: key, http: client, now: now}, nil
}

// Preflight mints fresh one-repository Issues read/write access before the host
// releases execution. It never uses a delegated token, fallback or token cache.
func (c *Client) Preflight(ctx context.Context, permission string) (*Access, error) {
	if permission != "read" && permission != "write" {
		return nil, ErrGitHubInput
	}
	now := c.now()
	appJWT, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{Issuer: c.account.AppID, IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)), ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute))}).SignedString(c.key)
	if err != nil {
		return nil, ErrGitHubAccess
	}
	request := struct {
		RepositoryIDs []json.Number     `json:"repository_ids"`
		Permissions   map[string]string `json:"permissions"`
	}{[]json.Number{json.Number(c.account.RepositoryID)}, map[string]string{"issues": permission}}
	raw, status, err := githubRequest(ctx, c.http, "POST", "/app/installations/"+c.account.InstallationID+"/access_tokens", appJWT, request)
	if err != nil || status != http.StatusCreated {
		return nil, ErrGitHubAccess
	}
	var response struct {
		Token               string            `json:"token"`
		ExpiresAt           string            `json:"expires_at"`
		RepositorySelection string            `json:"repository_selection"`
		Permissions         map[string]string `json:"permissions"`
		Repositories        []struct {
			ID       json.Number
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	if json.Unmarshal(raw, &response) != nil {
		return nil, ErrGitHubAccess
	}
	expiry, err := time.Parse(time.RFC3339, response.ExpiresAt)
	if err != nil || !expiry.After(c.now()) || !opaqueToken(response.Token) || response.RepositorySelection != "selected" || len(response.Repositories) != 1 || response.Repositories[0].ID.String() != c.account.RepositoryID || !strings.EqualFold(response.Repositories[0].FullName, c.account.Owner+"/"+c.account.Repository) || response.Permissions["issues"] != permission {
		return nil, ErrGitHubAccess
	}
	for name, value := range response.Permissions {
		if name == "issues" && value == permission || name == "metadata" && value == "read" {
			continue
		}
		return nil, ErrGitHubAccess
	}
	return &Access{account: c.account, http: c.http, token: response.Token, permission: permission, expiresAt: expiry, now: c.now}, nil
}
func opaqueToken(s string) bool {
	if s == "" {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

// githubRequest owns the destination and request shape. Results are bounded
// bytes only; callers map all errors/statuses to fixed safe diagnostics.
func githubRequest(ctx context.Context, client *http.Client, method, path, token string, body any) ([]byte, int, error) {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil || len(payload) > githubBodyLimit {
			return nil, 0, ErrGitHubInput
		}
	}
	endpoint := url.URL{Scheme: "https", Host: "api.github.com", Path: path}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, 0, errGitHubHTTP
	}
	req.GetBody = nil // no replayable-body hook, even if future transport settings change.
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("User-Agent", "aks-durable-agents")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, errGitHubHTTP
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, githubBodyLimit+1))
	if err != nil || len(raw) > githubBodyLimit || !utf8.Valid(raw) {
		return nil, resp.StatusCode, errGitHubHTTP
	}
	return raw, resp.StatusCode, nil
}

// Issue contains only the read result, never credential or response headers.
type Issue struct {
	Number           int64
	Title, Body, URL string
}
type Comment struct{ ID, URL string }

func (a *Access) usable(write bool) bool {
	return a != nil && a.http != nil && a.now != nil && a.token != "" && a.expiresAt.After(a.now()) && (a.permission == "write" || !write && a.permission == "read")
}
func (a *Access) issuePath(number int64) string {
	return "/repos/" + a.account.Owner + "/" + a.account.Repository + "/issues/" + strconv.FormatInt(number, 10)
}

// GetIssue does not acquire credentials; recovery must preflight outside the
// executor. Display URL and body remain data, never destinations to follow.
func (a *Access) GetIssue(ctx context.Context, number int64) (Issue, error) {
	if number <= 0 {
		return Issue{}, ErrGitHubInput
	}
	if !a.usable(false) {
		return Issue{}, ErrGitHubAccess
	}
	raw, status, err := githubRequest(ctx, a.http, "GET", a.issuePath(number), a.token, nil)
	if err != nil || status != http.StatusOK {
		return Issue{}, ErrGitHubRead
	}
	var response struct {
		Number int64  `json:"number"`
		Title  string `json:"title"`
		Body   string `json:"body"`
		URL    string `json:"html_url"`
	}
	if json.Unmarshal(raw, &response) != nil || response.Number != number || response.Title == "" || len(response.Title) > githubBodyLimit || !utf8.ValidString(response.Title) || !textOK(response.URL, 2048) {
		return Issue{}, ErrGitHubRead
	}
	return Issue{Number: response.Number, Title: response.Title, Body: response.Body, URL: response.URL}, nil
}

// CommentOnIssue performs one POST attempt. It does not record approval/intent
// or deduplicate: the future executor must reserve durably before calling it.
// A lost/invalid response cannot establish that GitHub made no comment.
func (a *Access) CommentOnIssue(ctx context.Context, number int64, body string) (Comment, error) {
	if number <= 0 || !utf8.ValidString(body) || len(body) > githubBodyLimit {
		return Comment{}, ErrGitHubInput
	}
	if !a.usable(true) {
		return Comment{}, ErrGitHubAccess
	}
	request := struct {
		Body string `json:"body"`
	}{body}
	raw, status, err := githubRequest(ctx, a.http, "POST", a.issuePath(number)+"/comments", a.token, request)
	if errors.Is(err, ErrGitHubInput) {
		return Comment{}, ErrGitHubInput
	}
	switch status {
	case 401, 403, 404, 410, 422, 429:
		return Comment{}, ErrGitHubRejected
	}
	if err != nil || status != http.StatusCreated {
		return Comment{}, ErrUnknownOutcome
	}
	var response struct {
		ID  json.Number `json:"id"`
		URL string      `json:"html_url"`
	}
	if json.Unmarshal(raw, &response) != nil || !decimalID(response.ID.String()) || !textOK(response.URL, 2048) {
		return Comment{}, ErrUnknownOutcome
	}
	return Comment{ID: response.ID.String(), URL: response.URL}, nil
}
