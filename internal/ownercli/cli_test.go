package ownercli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const tenant = "11111111-1111-4111-8111-111111111111"
const clientID = "22222222-2222-4222-8222-222222222222"
const scope = "api://aud/sessions.access"
const secret = "synthetic-private-token"

type tokenCredential struct {
	token  azcore.AccessToken
	err    error
	scopes []string
	mu     sync.Mutex
}

func (c *tokenCredential) GetToken(_ context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scopes = append(c.scopes, o.Scopes...)
	return c.token, c.err
}
func goodFactory(context.Context, string, string, string, io.Writer) (azcore.TokenCredential, error) {
	return &tokenCredential{token: azcore.AccessToken{Token: secret, ExpiresOn: time.Now().Add(time.Hour)}}, nil
}

type boundary struct {
	v1.UnimplementedSessionsServer
	mu           sync.Mutex
	calls        map[string]int
	get          *v1.Session
	approval     *v1.ApproveResponse
	resumed      *v1.Session
	fail         string
	execReq      *v1.ExecRequest
	approveReq   *v1.ApproveRequest
	resumeReq    *v1.ResumeRequest
	replayReq    *v1.ReplayRequest
	records      []*v1.LogRecord
	beforeExec   func()
	beforeResume func()
}

func parked() *v1.Session {
	return &v1.Session{Metadata: &v1.ResourceMetadata{Uid: "session-one"}, LastSeq: 7, ExecState: v1.ExecState_EXEC_AWAITING, PendingApproval: &v1.ApprovalRef{ExecutionId: "turn-one", ToolCallId: "call-one", RequestSeq: 6}}
}
func approved() *v1.ApproveResponse {
	s := parked()
	s.LastSeq = 8
	s.PendingApproval = nil
	return &v1.ApproveResponse{Session: s, Decision: &v1.LogRecord{Seq: 8, Event: &v1.Event{ExecutionId: "turn-one", Kind: v1.EventKind_EVENT_APPROVAL_RESULT, Body: &v1.Event_ApprovalResult{ApprovalResult: &v1.ApprovalResult{ToolCallId: "call-one", RequestSeq: 6, Approved: true}}}}}
}
func (b *boundary) hit(ctx context.Context, method string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls[method]++
	md, _ := metadata.FromIncomingContext(ctx)
	if got := md.Get("authorization"); len(got) != 1 || got[0] != "Bearer "+secret {
		return status.Error(codes.Unauthenticated, "wrong token")
	}
	if _, ok := ctx.Deadline(); !ok {
		return status.Error(codes.InvalidArgument, "missing deadline")
	}
	if b.fail == method {
		return status.Error(codes.Unavailable, "raw RPC "+secret)
	}
	return nil
}
func (b *boundary) count(method string) int { b.mu.Lock(); defer b.mu.Unlock(); return b.calls[method] }
func (b *boundary) CreateSession(ctx context.Context, q *v1.CreateSessionRequest) (*v1.Session, error) {
	if err := b.hit(ctx, "create"); err != nil {
		return nil, err
	}
	if q.Session.Harness != "harness" || q.Session.Model != "model" {
		return nil, status.Error(codes.InvalidArgument, "wrong route")
	}
	return &v1.Session{Metadata: &v1.ResourceMetadata{Uid: "session-one"}}, nil
}
func (b *boundary) GetSession(ctx context.Context, _ *v1.GetSessionRequest) (*v1.Session, error) {
	if err := b.hit(ctx, "get"); err != nil {
		return nil, err
	}
	return b.get, nil
}
func (b *boundary) Exec(q *v1.ExecRequest, s v1.Sessions_ExecServer) error {
	b.execReq = q
	if b.beforeExec != nil {
		b.beforeExec()
	}
	if err := b.hit(s.Context(), "exec"); err != nil {
		return err
	}
	return s.Send(&v1.ExecUpdate{Update: &v1.ExecUpdate_Session{Session: parked()}})
}
func (b *boundary) Approve(ctx context.Context, q *v1.ApproveRequest) (*v1.ApproveResponse, error) {
	b.approveReq = q
	if err := b.hit(ctx, "approval"); err != nil {
		return nil, err
	}
	return b.approval, nil
}
func (b *boundary) Resume(ctx context.Context, q *v1.ResumeRequest) (*v1.Session, error) {
	b.resumeReq = q
	if b.beforeResume != nil {
		b.beforeResume()
	}
	if err := b.hit(ctx, "resume"); err != nil {
		return nil, err
	}
	return b.resumed, nil
}
func (b *boundary) Replay(q *v1.ReplayRequest, s v1.Sessions_ReplayServer) error {
	if err := b.hit(s.Context(), "replay"); err != nil {
		return err
	}
	b.replayReq = q
	if q.Session != "session-one" || q.FromSeq < 1 || q.ToSeq < q.FromSeq {
		return status.Error(codes.InvalidArgument, "bad range")
	}
	records := b.records
	if records == nil {
		records = []*v1.LogRecord{{Seq: 5, Event: &v1.Event{ExecutionId: "turn-one", Kind: v1.EventKind_EVENT_TOOL_CALL, Body: &v1.Event_Tool{Tool: &v1.ToolCall{Id: "call-one", Tool: "publish", Args: &structpb.Struct{Fields: map[string]*structpb.Value{"draft": structpb.NewStringValue("private draft")}}}}}}, {Seq: 6, Event: &v1.Event{ExecutionId: "turn-one", Kind: v1.EventKind_EVENT_APPROVAL_REQUEST, Body: &v1.Event_Approval{Approval: &v1.ApprovalRequest{ToolCallId: "call-one"}}}}}
	}
	for _, r := range records {
		if r.Seq < q.FromSeq || r.Seq > q.ToSeq {
			continue
		}
		if err := s.Send(r); err != nil {
			return err
		}
	}
	return nil
}

func fixture(t *testing.T) (*boundary, []string) {
	t.Helper()
	h := httptest.NewTLSServer(nil)
	cert := h.TLS.Certificates[0]
	h.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	resumed := parked()
	resumed.LastSeq = 12 // Resume may park again after the approved decision at head 8.
	b := &boundary{calls: map[string]int{}, get: parked(), approval: approved(), resumed: resumed}
	g := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})))
	v1.RegisterSessionsServer(g, b)
	go func() { _ = g.Serve(ln) }()
	t.Cleanup(g.Stop)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	return b, []string{"--server", ln.Addr().String(), "--ca", ca, "--tls-name", "example.com", "--tenant", tenant, "--client-id", clientID, "--scope", scope}
}
func args(common []string, command string, extra ...string) []string {
	return append(append([]string{command}, common...), extra...)
}
func approvalArgs(common []string) []string {
	return args(common, "approve-run", "--session", "session-one", "--head", "7", "--execution", "turn-one", "--tool-call", "call-one", "--request-seq", "6")
}
func inputFile(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(p, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func startArgs(t *testing.T, common []string) []string {
	return args(common, "start", "--harness", "harness", "--model", "model", "--config", inputFile(t, `{"opaque":true}`), "--input", inputFile(t, "hello"))
}
func outcomes(t *testing.T, b *bytes.Buffer) []map[string]any {
	t.Helper()
	var result []map[string]any
	d := json.NewDecoder(b)
	for {
		var m map[string]any
		err := d.Decode(&m)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, m)
	}
	return result
}

func TestValidationBeforeCredential(t *testing.T) {
	_, common := fixture(t)
	cases := [][]string{nil, {"unknown"}, args(common, "inspect"), append(args(common, "inspect", "--session", "s"), "extra"), args(common, "inspect", "--session", "s", "--head", "7"), args(common, "start", "--session", "s"), args(common, "inspect", "--session", "s", "--token-file", "token")}
	for flag, values := range map[string][]string{"--server": {"localhost:443", "0.0.0.0:443", "192.0.2.1:443", "dns:///127.0.0.1:443", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:http"}, "--tenant": {"common", "not-guid", "00000000-0000-0000-0000-000000000000"}, "--client-id": {"bad"}, "--scope": {"", "sessions.access", "api://aud/.default", "api://aud/a api://aud/b"}, "--tls-name": {"", "https://example.com", "example.com:443"}, "--ca": {"/missing"}} {
		for _, v := range values {
			c := append([]string(nil), common...)
			for i := range c {
				if c[i] == flag {
					c[i+1] = v
					break
				}
			}
			cases = append(cases, args(c, "inspect", "--session", "s"))
		}
	}
	for i, c := range cases {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			called := false
			f := func(context.Context, string, string, string, io.Writer) (azcore.TokenCredential, error) {
				called = true
				return nil, errors.New(secret)
			}
			var out bytes.Buffer
			err := Run(context.Background(), c, &out, io.Discard, f)
			if err == nil || called {
				t.Fatalf("err=%v login=%v args=%v", err, called, c)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("leaked credential")
			}
		})
	}
}
func TestBoundedRegularFilesBeforeCredential(t *testing.T) {
	_, common := fixture(t)
	for _, path := range []string{t.TempDir(), "/dev/zero", inputFile(t, strings.Repeat("x", (1<<20)+1)), inputFile(t, "")} {
		a := startArgs(t, common)
		for i := range a {
			if a[i] == "--config" {
				a[i+1] = path
				break
			}
		}
		called := false
		f := func(context.Context, string, string, string, io.Writer) (azcore.TokenCredential, error) {
			called = true
			return nil, errors.New("login")
		}
		if err := Run(context.Background(), a, io.Discard, io.Discard, f); err == nil || called {
			t.Fatalf("path=%q err=%v login=%v", path, err, called)
		}
	}
}
func TestStartEmitsUIDBeforeExecAndPreservesConfig(t *testing.T) {
	b, common := fixture(t)
	var out bytes.Buffer
	b.beforeExec = func() {
		if !strings.Contains(out.String(), `"session":"session-one"`) {
			t.Error("UID not emitted before Exec")
		}
	}
	if err := Run(context.Background(), startArgs(t, common), &out, io.Discard, goodFactory); err != nil {
		t.Fatal(err)
	}
	if string(b.execReq.Config) != `{"opaque":true}` || b.execReq.Session != "session-one" || len(b.execReq.Inputs) != 1 || b.execReq.ExpectedLastSeq == nil || *b.execReq.ExpectedLastSeq != 0 {
		t.Fatalf("bad Exec: %v", b.execReq)
	}
	m := outcomes(t, &out)
	if len(m) != 2 || m[0]["outcome"] != "created" || m[1]["stage"] != "exec" {
		t.Fatalf("outcomes=%v", m)
	}
}
func TestInspectDisclosesPendingDraftWithoutMutation(t *testing.T) {
	b, common := fixture(t)
	var out bytes.Buffer
	if err := Run(context.Background(), args(common, "inspect", "--session", "session-one"), &out, io.Discard, goodFactory); err != nil {
		t.Fatal(err)
	}
	raw := out.String()
	m := outcomes(t, &out)
	if len(m) != 1 || m[0]["head"] != float64(7) || m[0]["pending"].(map[string]any)["requestSeq"] != "6" || !strings.Contains(raw, "request") {
		t.Fatalf("inspect=%s", raw)
	}
	// Inspect must retain the tool's structured arguments without schema knowledge.
	request, _ := json.Marshal(m[0]["request"])
	var e v1.Event
	if err := protojson.Unmarshal(request, &e); err != nil {
		t.Fatal(err)
	}
	if e.GetTool().GetArgs().GetFields()["draft"].GetStringValue() != "private draft" {
		t.Fatalf("draft missing: %s", raw)
	}
	if b.count("approval")+b.count("resume")+b.count("exec")+b.count("create") != 0 {
		t.Fatal("inspect mutated")
	}
}
func TestInspectRecoveredRequestAcrossSuspend(t *testing.T) {
	b, common := fixture(t)
	b.get.LastSeq = 301
	b.get.PendingApproval.RequestSeq = 300
	call := &v1.Event{ExecutionId: "turn-one", Kind: v1.EventKind_EVENT_TOOL_CALL, Body: &v1.Event_Tool{Tool: &v1.ToolCall{Id: "call-one", Tool: "publish", Args: &structpb.Struct{Fields: map[string]*structpb.Value{"draft": structpb.NewStringValue("recovered draft")}}}}}
	request := &v1.Event{ExecutionId: "turn-one", Kind: v1.EventKind_EVENT_APPROVAL_REQUEST, Body: &v1.Event_Approval{Approval: &v1.ApprovalRequest{ToolCallId: "call-one"}}}
	b.records = []*v1.LogRecord{{Seq: 298, Event: call}, {Seq: 299, Event: &v1.Event{Kind: v1.EventKind_EVENT_LIFECYCLE, Body: &v1.Event_Lifecycle{Lifecycle: &v1.Lifecycle{Kind: v1.Lifecycle_LIFECYCLE_SUSPEND}}}}, {Seq: 300, Event: request}}
	var out bytes.Buffer
	if err := Run(t.Context(), args(common, "inspect", "--session", "session-one"), &out, io.Discard, goodFactory); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "recovered draft") || b.replayReq.FromSeq != 44 || b.replayReq.ToSeq != 300 || b.count("approval") != 0 || b.count("resume") != 0 {
		t.Fatalf("recovered inspect: %s, range=%v", &out, b.replayReq)
	}
	// A matching tool ID from another execution must not substitute for the request.
	call.ExecutionId = "different-turn"
	out.Reset()
	if err := Run(t.Context(), args(common, "inspect", "--session", "session-one"), &out, io.Discard, goodFactory); err == nil || !strings.Contains(out.String(), `"outcome":"unknown"`) {
		t.Fatalf("unbound request accepted: %v %s", err, &out)
	}
}

func TestApproveChecksTupleAndResumeWireHead(t *testing.T) {
	b, common := fixture(t)
	var out bytes.Buffer
	b.beforeResume = func() {
		if !strings.Contains(out.String(), `"outcome":"approved"`) {
			t.Error("approval not reported before Resume")
		}
	}
	if err := Run(context.Background(), approvalArgs(common), &out, io.Discard, goodFactory); err != nil {
		t.Fatal(err)
	}
	q := b.approveReq
	if q.Session != "session-one" || q.ExecutionId != "turn-one" || q.ToolCallId != "call-one" || q.RequestSeq != 6 || q.Approved == nil || !*q.Approved || q.Identity != nil {
		t.Fatalf("approval binding=%v", q)
	}
	if b.resumeReq.ExpectedLastSeq == nil || *b.resumeReq.ExpectedLastSeq != 8 {
		t.Fatalf("Resume=%v", b.resumeReq)
	}
	m := outcomes(t, &out)
	if len(m) != 2 || m[0]["outcome"] != "approved" || m[1]["outcome"] != "resumed" || m[1]["pending"] == nil {
		t.Fatalf("outcomes=%v", m)
	}
}
func TestStaleTupleStopsBeforeApprove(t *testing.T) {
	for _, field := range []string{"--head", "--execution", "--tool-call", "--request-seq"} {
		t.Run(field, func(t *testing.T) {
			b, c := fixture(t)
			a := approvalArgs(c)
			for i := range a {
				if a[i] == field {
					if field == "--head" {
						a[i+1] = "9"
					} else if field == "--request-seq" {
						a[i+1] = "5"
					} else {
						a[i+1] = "wrong"
					}
					break
				}
			}
			if err := Run(context.Background(), a, io.Discard, io.Discard, goodFactory); err == nil || b.count("get") != 1 || b.count("approval") != 0 || b.count("resume") != 0 {
				t.Fatalf("stale allowed: %v", err)
			}
		})
	}
}
func TestLostMutationReplyStopsWithoutRepeatOrRawLeak(t *testing.T) {
	for _, stage := range []string{"create", "exec", "approval", "resume"} {
		t.Run(stage, func(t *testing.T) {
			b, c := fixture(t)
			b.fail = stage
			a := approvalArgs(c)
			if stage == "create" || stage == "exec" {
				a = startArgs(t, c)
			}
			var out bytes.Buffer
			err := Run(context.Background(), a, &out, io.Discard, goodFactory)
			if err == nil || strings.Contains(err.Error()+out.String(), secret) || strings.Contains(err.Error(), "raw RPC") {
				t.Fatalf("unsafe error/output: %v %s", err, &out)
			}
			if b.count(stage) != 1 {
				t.Fatalf("repeated %s %d", stage, b.count(stage))
			}
			m := outcomes(t, &out)
			last := m[len(m)-1]
			want := "unknown"
			if stage == "exec" {
				want = "partial"
			}
			if last["stage"] != stage || last["outcome"] != want {
				t.Fatalf("outcomes=%v", m)
			}
			if stage == "approval" && b.count("resume") != 0 {
				t.Fatal("resumed after unknown approval")
			}
			if stage == "exec" && m[0]["session"] != "session-one" {
				t.Fatal("lost UID")
			}
		})
	}
}
func TestMalformedApprovalNeverResumes(t *testing.T) {
	for _, mutate := range []func(*v1.ApproveResponse){func(r *v1.ApproveResponse) { r.Session = nil }, func(r *v1.ApproveResponse) { r.Decision = nil }, func(r *v1.ApproveResponse) { r.Session.Metadata.Uid = "other" }, func(r *v1.ApproveResponse) { r.Decision.Seq = 0 }, func(r *v1.ApproveResponse) { r.Session.LastSeq = 7 }, func(r *v1.ApproveResponse) { r.Decision.Event.ExecutionId = "other" }, func(r *v1.ApproveResponse) { r.Decision.Event.Kind = v1.EventKind_EVENT_OUTPUT }, func(r *v1.ApproveResponse) { r.Decision.Event.GetApprovalResult().Approved = false }, func(r *v1.ApproveResponse) { r.Decision.Event.GetApprovalResult().RequestSeq = 5 }, func(r *v1.ApproveResponse) { r.Decision.Event.GetApprovalResult().ToolCallId = "other" }} {
		b, c := fixture(t)
		mutate(b.approval)
		var out bytes.Buffer
		if err := Run(context.Background(), approvalArgs(c), &out, io.Discard, goodFactory); err == nil || b.count("resume") != 0 {
			t.Fatalf("accepted malformed approval: %v", err)
		}
		if !strings.Contains(out.String(), `"outcome":"unknown"`) {
			t.Fatalf("missing unknown: %s", &out)
		}
	}
}

type failWriter struct{ writes, allow int }

func (w *failWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes > w.allow {
		return 0, errors.New("private writer " + secret)
	}
	return len(p), nil
}
func TestOutputFailureStopsNextMutation(t *testing.T) {
	for _, command := range []string{"start", "approve-run"} {
		b, c := fixture(t)
		a := approvalArgs(c)
		if command == "start" {
			a = startArgs(t, c)
		}
		err := Run(context.Background(), a, &failWriter{}, io.Discard, goodFactory)
		if err == nil || strings.Contains(err.Error(), secret) || b.count("exec") != 0 || b.count("resume") != 0 {
			t.Fatalf("continued after writer failure: %v", err)
		}
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestShortOutputStopsNextMutation(t *testing.T) {
	for _, command := range []string{"start", "approve-run"} {
		b, common := fixture(t)
		a := approvalArgs(common)
		if command == "start" {
			a = startArgs(t, common)
		}
		if err := Run(t.Context(), a, shortWriter{}, io.Discard, goodFactory); err == nil || b.count("exec") != 0 || b.count("resume") != 0 {
			t.Fatalf("continued after partial output: %v", err)
		}
	}
}

func TestTLSAndCredentialFailuresNeverReachRPC(t *testing.T) {
	for _, mode := range []string{"name", "ca", "empty", "expired", "credential-error", "factory-error"} {
		t.Run(mode, func(t *testing.T) {
			b, c := fixture(t)
			f := CredentialFactory(goodFactory)
			switch mode {
			case "name":
				c[5] = "wrong.example"
			case "ca":
				h := httptest.NewTLSServer(nil)
				h.Close()
				c[3] = inputFile(t, "not a CA")
			case "factory-error":
				f = func(context.Context, string, string, string, io.Writer) (azcore.TokenCredential, error) {
					return nil, errors.New(secret)
				}
			default:
				cred := &tokenCredential{token: azcore.AccessToken{Token: secret, ExpiresOn: time.Now().Add(time.Hour)}}
				if mode == "empty" {
					cred.token.Token = ""
				}
				if mode == "expired" {
					cred.token.ExpiresOn = time.Now().Add(-time.Second)
				}
				if mode == "credential-error" {
					cred.err = errors.New(secret)
				}
				f = func(context.Context, string, string, string, io.Writer) (azcore.TokenCredential, error) {
					return cred, nil
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			var out bytes.Buffer
			err := Run(ctx, args(c, "inspect", "--session", "session-one"), &out, io.Discard, f)
			if err == nil || strings.Contains(err.Error()+out.String(), secret) || b.count("get") != 0 {
				t.Fatalf("unsafe %s: %v %s calls=%d", mode, err, &out, b.count("get"))
			}
		})
	}
}

// Compile-time coverage of the exported integration seam.
var _ CredentialFactory = DeviceCredential
