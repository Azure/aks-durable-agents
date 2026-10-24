// Package ownercli implements the authenticated, TLS-only owner client.
package ownercli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/protojson"
)

// CredentialFactory authenticates one explicitly configured delegated caller.
// The production command always supplies DeviceCredential; there is no CLI alternate provider.
type CredentialFactory func(context.Context, string, string, string, io.Writer) (azcore.TokenCredential, error)

type options struct {
	command, server, ca, name, tenant, client, scope        string
	harness, model, config, input, session, execution, tool string
	head, request                                           int64
	configBytes, inputBytes                                 []byte
	roots                                                   *x509.CertPool
}

const fileLimit = 1 << 20

var guid = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var dnsName = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)

func validGUID(s string) bool {
	return guid.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}
func validScope(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "api" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && len(u.Path) > 1 && !strings.HasSuffix(u.Path, "/.default") && !strings.ContainsAny(s, " \t\r\n")
}
func boundedFile(path string) ([]byte, error) {
	// Refuse special files before opening (notably blocking FIFOs). The invoking host is trusted.
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > fileLimit {
		return nil, errors.New("file must be a regular file of 1 to 1048576 bytes")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open input file")
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("input is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, fileLimit+1))
	if err != nil || len(b) == 0 || len(b) > fileLimit {
		return nil, errors.New("file must be a regular file of 1 to 1048576 bytes")
	}
	return b, nil
}
func parse(args []string) (options, error) {
	var o options
	if len(args) == 0 {
		return o, errors.New("command required: start, inspect, approve-run")
	}
	o.command = args[0]
	f := flag.NewFlagSet("owner-client", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	for _, v := range []struct {
		p *string
		n string
	}{{&o.server, "server"}, {&o.ca, "ca"}, {&o.name, "tls-name"}, {&o.tenant, "tenant"}, {&o.client, "client-id"}, {&o.scope, "scope"}} {
		f.StringVar(v.p, v.n, "", "required")
	}
	switch o.command {
	case "start":
		for _, v := range []struct {
			p *string
			n string
		}{{&o.harness, "harness"}, {&o.model, "model"}, {&o.config, "config"}, {&o.input, "input"}} {
			f.StringVar(v.p, v.n, "", "required")
		}
	case "approve-run":
		f.Int64Var(&o.head, "head", 0, "reviewed head")
		f.Int64Var(&o.request, "request-seq", 0, "reviewed request sequence")
		f.StringVar(&o.execution, "execution", "", "reviewed execution")
		f.StringVar(&o.tool, "tool-call", "", "reviewed tool call")
		fallthrough
	case "inspect":
		f.StringVar(&o.session, "session", "", "session UID")
	default:
		return o, errors.New("unknown command: use start, inspect, approve-run")
	}
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return o, errors.New("invalid flags or positional arguments")
	}
	host, port, err := net.SplitHostPort(o.server)
	ip := net.ParseIP(host)
	p, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || p < 1 || p > 65535 {
		return o, errors.New("server must be a literal loopback IP:port")
	}
	if !validGUID(o.tenant) || !validGUID(o.client) || !validScope(o.scope) {
		return o, errors.New("explicit GUID tenant, GUID client-id and full delegated scope required")
	}
	if len(o.name) > 253 || (!dnsName.MatchString(o.name) && net.ParseIP(o.name) == nil) {
		return o, errors.New("tls-name must be a certificate DNS name or IP")
	}
	if o.command == "start" {
		if strings.TrimSpace(o.harness) == "" || strings.TrimSpace(o.model) == "" {
			return o, errors.New("harness and model required")
		}
		if o.configBytes, err = boundedFile(o.config); err != nil {
			return o, fmt.Errorf("config: %w", err)
		}
		if o.inputBytes, err = boundedFile(o.input); err != nil {
			return o, fmt.Errorf("input: %w", err)
		}
	} else if strings.TrimSpace(o.session) == "" {
		return o, errors.New("session required")
	}
	if o.command == "approve-run" && (o.head <= 0 || o.request <= 0 || o.request > o.head || strings.TrimSpace(o.execution) == "" || strings.TrimSpace(o.tool) == "") {
		return o, errors.New("positive head/request-seq and reviewed execution/tool-call required")
	}
	ca, err := boundedFile(o.ca)
	if err != nil {
		return o, fmt.Errorf("ca: %w", err)
	}
	o.roots = x509.NewCertPool()
	if !o.roots.AppendCertsFromPEM(ca) {
		return o, errors.New("ca must contain a PEM certificate")
	}
	return o, nil
}

type bearer struct {
	credential azcore.TokenCredential
	scope      string
}

func (b bearer) token(ctx context.Context) (string, error) {
	t, err := b.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{b.scope}})
	if err != nil || t.Token == "" || strings.ContainsAny(t.Token, " \t\r\n") || !t.ExpiresOn.After(time.Now().Add(30*time.Second)) {
		return "", errors.New("delegated credential unavailable, empty or expiring")
	}
	return t.Token, nil
}
func (b bearer) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	info, ok := credentials.RequestInfoFromContext(ctx)
	if !ok || credentials.CheckSecurityLevel(info.AuthInfo, credentials.PrivacyAndIntegrity) != nil {
		return nil, errors.New("verified TLS required")
	}
	token, err := b.token(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]string{"authorization": "Bearer " + token}, nil
}
func (bearer) RequireTransportSecurity() bool { return true }

type outcome struct {
	Stage   string          `json:"stage"`
	Outcome string          `json:"outcome"`
	Session string          `json:"session"`
	Head    int64           `json:"head"`
	Pending json.RawMessage `json:"pending,omitempty"`
	Request json.RawMessage `json:"request,omitempty"`
}

func emit(w io.Writer, stage, result string, s *v1.Session, request *v1.Event) error {
	o := outcome{Stage: stage, Outcome: result, Session: s.GetMetadata().GetUid(), Head: s.GetLastSeq()}
	if s.GetPendingApproval() != nil {
		o.Pending, _ = protojson.Marshal(s.PendingApproval)
	}
	if request != nil {
		o.Request, _ = protojson.Marshal(request)
	}
	b, err := json.Marshal(o)
	if err != nil {
		return errors.New("cannot encode outcome; stop and inspect any possibly committed operation")
	}
	b = append(b, '\n')
	if n, err := w.Write(b); err != nil || n != len(b) {
		return errors.New("output failed; stop and inspect any possibly committed operation")
	}
	return nil
}
func failed(w io.Writer, stage, result string, s *v1.Session) error {
	if err := emit(w, stage, result, s, nil); err != nil {
		return err
	}
	return fmt.Errorf("%s outcome %s; stop and reconcile with read-only inspect; no automatic retry", stage, result)
}
func validSession(s *v1.Session, uid string) bool {
	return s != nil && s.GetMetadata().GetUid() != "" && (uid == "" || s.GetMetadata().GetUid() == uid) && s.LastSeq >= 0
}

// Run executes one command. stdout carries JSON lines; prompt carries private device sign-in instructions.
// A returned error never authorizes retrying a mutation: the reply may have been lost after commit.
func Run(ctx context.Context, args []string, stdout, prompt io.Writer, factory CredentialFactory) error {
	o, err := parse(args)
	if err != nil {
		return err
	}
	if stdout == nil || prompt == nil || factory == nil {
		return errors.New("output, prompt and credential factory required")
	}
	credential, err := factory(ctx, o.tenant, o.client, o.scope, prompt)
	if err != nil || credential == nil {
		return errors.New("delegated sign-in failed")
	}
	auth := bearer{credential: credential, scope: o.scope}
	if _, err := auth.token(ctx); err != nil {
		return err
	}
	c, err := client.Dial("passthrough:///"+o.server, client.WithDialOptions(
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.roots, ServerName: o.name})),
		grpc.WithPerRPCCredentials(auth), grpc.WithNoProxy(), grpc.WithDisableRetry(), grpc.WithDisableServiceConfig(),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", o.server)
		}),
	))
	if err != nil {
		return errors.New("TLS client initialization failed")
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if o.command == "start" {
		return start(ctx, c, o, stdout)
	}
	s, err := c.GetSession(ctx, o.session)
	if err != nil || !validSession(s, o.session) {
		return failed(stdout, "inspect", "unknown", nil)
	}
	if o.command == "inspect" {
		var request *v1.Event
		if p := s.PendingApproval; p != nil {
			// The host journals TOOL_CALL immediately before its owned APPROVAL_REQUEST.
			if p.RequestSeq < 2 || p.RequestSeq > s.LastSeq {
				return failed(stdout, "inspect", "unknown", s)
			}
			records, err := c.Replay(ctx, o.session, p.RequestSeq-1, p.RequestSeq)
			if err != nil || len(records) != 2 {
				return failed(stdout, "inspect", "unknown", s)
			}
			call, req := records[0], records[1]
			e := call.GetEvent()
			r := req.GetEvent()
			if call.GetSeq() != p.RequestSeq-1 || req.GetSeq() != p.RequestSeq || e.GetKind() != v1.EventKind_EVENT_TOOL_CALL || e.GetExecutionId() != p.ExecutionId || e.GetTool().GetId() != p.ToolCallId || r.GetKind() != v1.EventKind_EVENT_APPROVAL_REQUEST || r.GetExecutionId() != p.ExecutionId || r.GetApproval().GetToolCallId() != p.ToolCallId {
				return failed(stdout, "inspect", "unknown", s)
			}
			request = e
		}
		return emit(stdout, "inspect", "inspected", s, request)
	}
	p := s.PendingApproval
	if p == nil || s.LastSeq != o.head || p.ExecutionId != o.execution || p.ToolCallId != o.tool || p.RequestSeq != o.request {
		return errors.New("reviewed head or pending tuple changed; inspect and review again")
	}
	yes := true
	r, err := c.Sessions().Approve(ctx, &v1.ApproveRequest{Session: o.session, ExecutionId: o.execution, ToolCallId: o.tool, RequestSeq: o.request, Approved: &yes})
	if err != nil || !validApproval(r, o) {
		return failed(stdout, "approval", "unknown", s)
	}
	if err := emit(stdout, "approval", "approved", r.Session, nil); err != nil {
		return err
	}
	// SDK Resume omits the precondition. Use the raw stub with the approval response's exact head.
	head := r.Session.LastSeq
	resumed, err := c.Sessions().Resume(ctx, &v1.ResumeRequest{Session: o.session, ExpectedLastSeq: &head})
	if err != nil || !validSession(resumed, o.session) || resumed.LastSeq < head {
		return failed(stdout, "resume", "unknown", r.Session)
	}
	// Resume may park at another approval. A successful RPC is not proof of publication/completion.
	return emit(stdout, "resume", "resumed", resumed, nil)
}
func validApproval(r *v1.ApproveResponse, o options) bool {
	if r == nil || !validSession(r.Session, o.session) || r.Decision == nil {
		return false
	}
	d := r.Decision
	e := d.GetEvent()
	a := e.GetApprovalResult()
	return d.Seq > o.head && r.Session.LastSeq == d.Seq && e.GetKind() == v1.EventKind_EVENT_APPROVAL_RESULT && e.GetExecutionId() == o.execution && a != nil && a.Approved && a.ToolCallId == o.tool && a.RequestSeq == o.request && r.Session.PendingApproval == nil
}
func start(ctx context.Context, c *client.Client, o options, w io.Writer) error {
	s, err := c.CreateSession(ctx, &v1.Session{Harness: o.harness, Model: o.model})
	if err != nil || !validSession(s, "") {
		return failed(w, "create", "unknown", nil)
	}
	if err := emit(w, "create", "created", s, nil); err != nil {
		return err
	}
	head := s.LastSeq
	result, err := c.Exec(ctx, client.ExecOptions{Session: s.Metadata.Uid, Harness: o.harness, Config: o.configBytes, Inputs: []string{string(o.inputBytes)}, ExpectedLastSeq: &head})
	if err != nil || result == nil || !validSession(result.Session, s.Metadata.Uid) {
		return failed(w, "exec", "partial", s)
	}
	for _, r := range result.Records {
		if r.GetEvent().GetKind() == v1.EventKind_EVENT_ERROR {
			return failed(w, "exec", "partial", s)
		}
	}
	result.Session.LastSeq = result.LastSeq
	return emit(w, "exec", "executed", result.Session, nil)
}
