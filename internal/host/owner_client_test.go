package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/internal/ownercli"
	"github.com/Azure/aks-durable-agents/internal/sessionfixture"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"github.com/agent-primitives/sessions/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const clientOwnerOID = "0a0a0a0a-0000-4000-8000-000000000001"
const clientOtherOID = "0b0b0b0b-0000-4000-8000-000000000002"
const ownerConfig = `{"system_prompt":"Draft fictional release notes.","reference":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`

type ownerTokenCredential string

func (c ownerTokenCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: string(c), ExpiresOn: time.Now().Add(time.Hour)}, nil
}
func ownerFactory(token string) ownercli.CredentialFactory {
	return func(context.Context, string, string, string, io.Writer) (azcore.TokenCredential, error) {
		return ownerTokenCredential(token), nil
	}
}

type ownerHost struct {
	f                      *hostFixture
	addr, data             string
	sign                   func(string) string
	stopHost, stopExecutor func()
}

func newOwnerHost(t *testing.T, addr string) *ownerHost {
	t.Helper()
	f := newHostFixture(t)
	raw, err := os.MkdirTemp("", "owner-")
	if err != nil {
		t.Fatal(err)
	}
	data, err := filepath.EvalSymlinks(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(data) })
	if err := sessionfixture.RunCLI(t.Context(), []string{"bridge-init", "--data", data}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	harness, _ := startBridgeRole(t, "bridge-harness", "--addr", "127.0.0.1:0", "--model", f.config.Deployment)
	_, stopExecutor := startBridgeRole(t, "executor", "--scenario", "source-demo-v1", "--database", filepath.Join(data, "publications.db"))
	f.config.Harnesses = map[string]string{demoBridgeHarness: harness["addr"].(string)}
	f.config.Journal, f.config.ToolExecutors = filepath.Join(data, "journal.db"), filepath.Join(data, "tools.json")
	identity, sign := entraFixture(t)
	f.config.Mode, f.config.Identity = authn.Required, identity
	f.config.Approvers = []api.CallerIdentity{{Issuer: fixtureIssuer, Subject: clientOwnerOID}}
	app, err := newApplication(t.Context(), f.config, fixtureCredential{t}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go app.sessions.Serve(ln)
	return &ownerHost{f: f, addr: ln.Addr().String(), data: data, sign: sign, stopHost: app.Close, stopExecutor: stopExecutor}
}

func ownerArgs(server, ca string) []string {
	return []string{"--server", server, "--ca", ca, "--tls-name", "example.com", "--tenant", "11111111-2222-3333-4444-555555555555", "--client-id", "12345678-1234-1234-1234-123456789abc", "--scope", "api://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/sessions.access"}
}
func runOwner(t *testing.T, common []string, factory ownercli.CredentialFactory, command string, args ...string) ([]map[string]any, error) {
	t.Helper()
	var out bytes.Buffer
	all := append([]string{command}, common...)
	all = append(all, args...)
	err := ownercli.Run(t.Context(), all, &out, io.Discard, factory)
	var rows []map[string]any
	dec := json.NewDecoder(&out)
	for dec.More() {
		var row map[string]any
		if e := dec.Decode(&row); e != nil {
			t.Fatal(e)
		}
		rows = append(rows, row)
	}
	return rows, err
}
func ownerStart(t *testing.T, common []string, factory ownercli.CredentialFactory) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{"config": ownerConfig, "input": "Draft fictional release facts."} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := runOwner(t, common, factory, "start", "--harness", demoBridgeHarness, "--model", "test-deployment", "--config", filepath.Join(dir, "config"), "--input", filepath.Join(dir, "input"))
	if err != nil {
		t.Fatalf("start: %v, %v", err, rows)
	}
	if len(rows) < 2 {
		t.Fatalf("missing create/Exec outcomes: %v", rows)
	}
	uid, _ := rows[0]["session"].(string)
	if uid == "" {
		t.Fatalf("missing UID before execution: %v", rows)
	}
	return uid
}
func ownerActionArgs(s *v1.Session) []string {
	p := s.GetPendingApproval()
	return []string{"--session", s.GetMetadata().GetUid(), "--head", strconv.FormatInt(s.GetLastSeq(), 10), "--execution", p.GetExecutionId(), "--tool-call", p.GetToolCallId(), "--request-seq", strconv.FormatInt(p.GetRequestSeq(), 10)}
}
func ownerView(t *testing.T, h *ownerHost, uid, subject string) *v1.Session {
	t.Helper()
	creds, err := credentials.NewClientTLSFromFile(h.f.config.TLSCert, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.Dial(h.addr, client.WithDialOptions(grpc.WithTransportCredentials(creds)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.GetSession(bearer(t.Context(), "Bearer "+h.sign(subject)), uid)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func ownerReplayProof(t *testing.T, h *ownerHost, uid string) ([]byte, error) {
	t.Helper()
	h.stopHost()
	h.stopExecutor()
	scratch := t.TempDir()
	if err := os.Chmod(scratch, 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(h.data)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		b, e := os.ReadFile(filepath.Join(h.data, entry.Name()))
		if e != nil {
			return nil, e
		}
		if e = os.WriteFile(filepath.Join(scratch, entry.Name()), b, 0600); e != nil {
			return nil, e
		}
	}
	var out bytes.Buffer
	err = sessionfixture.RunCLI(t.Context(), []string{"bridge-verify", "--journal", filepath.Join(scratch, "journal.db"), "--session", uid, "--model", "test-deployment", "--config-sha256", fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(ownerConfig)))}, &out, io.Discard)
	return out.Bytes(), err
}

// The real host, TLS verifier, bridge and client orchestration; model and Entra
// identities are synthetic fixtures, never live approval qualification.
func TestOwnerClientRequiredHost(t *testing.T) {
	h := newOwnerHost(t, "127.0.0.1:0")
	common := ownerArgs(h.addr, h.f.config.TLSCert)
	owner := ownerFactory(h.sign(clientOwnerOID))
	other := ownerFactory(h.sign(clientOtherOID))
	uid := ownerStart(t, common, owner)
	s := ownerView(t, h, uid, clientOwnerOID)
	if s.GetPendingApproval() == nil {
		t.Fatal("did not park")
	}
	if p, r := bridgeRuntimeInventory(t, h.data); p != 0 || r != 0 {
		t.Fatal("publication before approval")
	}
	if _, err := runOwner(t, common, other, "inspect", "--session", uid); err == nil {
		t.Fatal("foreign owner read accepted")
	}
	inspect, err := runOwner(t, common, owner, "inspect", "--session", uid)
	b, _ := json.Marshal(inspect)
	if err != nil || !strings.Contains(string(b), "Fixed release draft.") {
		t.Fatalf("pending draft absent: %v %s", err, b)
	}
	stale := ownerActionArgs(s)
	stale[3] = "1"
	if _, err := runOwner(t, common, owner, "approve-run", stale...); err == nil {
		t.Fatal("stale reviewed head accepted")
	}
	otherUID := ownerStart(t, common, other)
	otherSession := ownerView(t, h, otherUID, clientOtherOID)
	if _, err := runOwner(t, common, other, "approve-run", ownerActionArgs(otherSession)...); err == nil {
		t.Fatal("ownership alone granted approval")
	}
	if p, r := bridgeRuntimeInventory(t, h.data); p != 0 || r != 0 {
		t.Fatal("denied approval caused publication")
	}
	rows, err := runOwner(t, common, owner, "approve-run", ownerActionArgs(s)...)
	if err != nil || len(rows) != 2 || rows[0]["stage"] != "approval" || rows[0]["outcome"] != "approved" || rows[1]["stage"] != "resume" || rows[1]["outcome"] != "resumed" {
		t.Fatalf("separate outcomes: %v %v", rows, err)
	}
	if p, r := bridgeRuntimeInventory(t, h.data); p != 1 || r != 1 || h.f.models.Load() != 2 {
		t.Fatal("expected two drafts and one durable publication")
	}
	if _, err := runOwner(t, common, owner, "approve-run", ownerActionArgs(s)...); err == nil {
		t.Fatal("repeated action did not stop")
	}
	proof, err := ownerReplayProof(t, h, uid)
	var v struct {
		Completed     bool `json:"completed"`
		ProviderCalls int  `json:"provider_calls"`
		ExecutorCalls int  `json:"executor_calls"`
	}
	if err != nil || json.Unmarshal(proof, &v) != nil || !v.Completed || v.ProviderCalls != 0 || v.ExecutorCalls != 0 {
		t.Fatalf("zero-call replay: %s %v", proof, err)
	}
}
