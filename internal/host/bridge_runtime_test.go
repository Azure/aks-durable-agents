package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/internal/sessionfixture"
	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"github.com/agent-primitives/sessions/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func startBridgeRole(t *testing.T, args ...string) (map[string]any, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	r, w := io.Pipe()
	done := make(chan error, 1)
	go func() { err := sessionfixture.RunCLI(ctx, args, w, io.Discard); _ = w.CloseWithError(err); done <- err }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			_ = r.Close()
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Errorf("bridge role stop: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("bridge role did not stop")
			}
		})
	}
	t.Cleanup(stop)
	ready := make(chan error, 1)
	info := map[string]any{}
	go func() { ready <- json.NewDecoder(r).Decode(&info) }()
	select {
	case err := <-ready:
		if err != nil {
			stop()
			t.Fatalf("bridge readiness: %v", err)
		}
	case <-time.After(5 * time.Second):
		stop()
		t.Fatal("bridge readiness timeout")
	}
	return info, stop
}
func bridgeRuntimeInventory(t *testing.T, data string) (int, int) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(data, "publications.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var p, r int
	if err := db.QueryRow("SELECT (SELECT COUNT(*) FROM publications),(SELECT COUNT(*) FROM receipts)").Scan(&p, &r); err != nil {
		t.Fatal(err)
	}
	return p, r
}

// Actual production host, published fixture roles, verified TLS and synthetic
// signed-in owner/approver. This is not live Entra or workload-identity proof.
func TestBridgeRuntimeRequiredOwnerRestartApproveAndReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newHostFixture(t)
	raw, err := os.MkdirTemp("", "bridge-")
	if err != nil {
		t.Fatal(err)
	}
	data, err := filepath.EvalSymlinks(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(data) })
	var out bytes.Buffer
	if err := sessionfixture.RunCLI(ctx, []string{"bridge-init", "--data", data}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	harness, _ := startBridgeRole(t, "bridge-harness", "--addr", "127.0.0.1:0", "--model", f.config.Deployment)
	_, stopExecutor := startBridgeRole(t, "executor", "--scenario", "source-demo-v1", "--database", filepath.Join(data, "publications.db"))
	f.config.Harnesses = map[string]string{"demo-release-notes": harness["addr"].(string)}
	f.config.Journal = filepath.Join(data, "journal.db")
	f.config.ToolExecutors = filepath.Join(data, "tools.json")
	identity, sign := entraFixture(t)
	f.config.Mode, f.config.Identity = authn.Required, identity
	const ownerOID = "0a0a0a0a-" + "0000-4000-8000-000000000001"
	const outsiderOID = "0b0b0b0b-" + "0000-4000-8000-000000000002"
	f.config.Approvers = []api.CallerIdentity{{Issuer: fixtureIssuer, Subject: ownerOID}}
	ownerToken, outsiderToken := sign(ownerOID), sign(outsiderOID)
	owner, outsider := bearer(ctx, "Bearer "+ownerToken), bearer(ctx, "Bearer "+outsiderToken)
	_, c, stopHost := f.start(t)
	reference := "sha256:" + strings.Repeat("a", 64)
	config := []byte(`{"system_prompt":"New bridge instructions from opaque Config.","reference":"` + reference + `"}`)
	if _, err := c.CreateSession(owner, &v1.Session{Harness: demoBridgeHarness, Model: "other"}); err == nil || f.models.Load() != 0 {
		t.Fatal("wrong model admitted")
	}
	created, err := c.CreateSession(owner, &v1.Session{Harness: "demo-release-notes", Model: f.config.Deployment})
	if err != nil {
		t.Fatal(err)
	}
	uid := created.GetMetadata().GetUid()
	turn, err := c.Exec(owner, client.ExecOptions{Session: uid, Config: config, Inputs: []string{"Draft fictional release facts."}})
	if err != nil || turn.Session.GetPendingApproval() == nil {
		t.Fatalf("bridge did not park: %v", err)
	}
	d := decision(t, turn.Session, true)
	if p, r := bridgeRuntimeInventory(t, data); p != 0 || r != 0 || f.models.Load() != 1 {
		t.Fatal("publication before consent or repeated draft")
	}
	stopHost()
	stopExecutor()
	_, stopExecutor = startBridgeRole(t, "executor", "--scenario", "source-demo-v1", "--database", filepath.Join(data, "publications.db"))
	_, c, stopHost = f.start(t)
	resumedView, err := c.GetSession(owner, uid)
	if err != nil || resumedView.GetPendingApproval() == nil || resumedView.GetPendingApproval().GetRequestSeq() != d.RequestSeq {
		t.Fatal("pending approval did not survive restart")
	}
	if _, err := c.Approve(outsider, uid, d); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unauthorized approval: %v", err)
	}
	stale := d
	stale.RequestSeq++
	if _, err := c.Approve(owner, uid, stale); err == nil {
		t.Fatal("stale approval accepted")
	}
	if _, err := c.Approve(owner, uid, d); err != nil {
		t.Fatal(err)
	}
	if p, r := bridgeRuntimeInventory(t, data); p != 0 || r != 0 {
		t.Fatal("Approve automatically published")
	}
	if _, err := c.Resume(owner, uid, false); err != nil {
		t.Fatal(err)
	}
	records, err := c.Replay(owner, uid, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p, r := bridgeRuntimeInventory(t, data); p != 1 || r != 1 || f.models.Load() != 1 {
		t.Fatal("not one model draft and one durable publication")
	}
	f.mu.Lock()
	captured := string(f.boundary)
	f.mu.Unlock()
	if !strings.Contains(captured, "New bridge instructions from opaque Config.") {
		t.Fatal("exported instruction projection did not reach model")
	}
	f.assertNoSecrets(t, records, ownerToken, outsiderToken)
	stopHost()
	stopExecutor()
	// Stopped writers give a consistent complete copy; never drop committed WAL.
	scratch := t.TempDir()
	if err := os.Chmod(scratch, 0700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(data, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(scratch, entry.Name()), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	out.Reset()
	args := []string{"bridge-verify", "--journal", filepath.Join(scratch, "journal.db"), "--session", uid, "--model", f.config.Deployment, "--config-sha256", fmt.Sprintf("sha256:%x", sha256.Sum256(config))}
	err = sessionfixture.RunCLI(ctx, args, &out, io.Discard)
	var proof struct {
		Completed     bool   `json:"completed"`
		HeadHash      string `json:"head_hash"`
		ProviderCalls int    `json:"provider_calls"`
		ExecutorCalls int    `json:"executor_calls"`
	}
	if jsonErr := json.Unmarshal(out.Bytes(), &proof); err != nil || jsonErr != nil || !proof.Completed || proof.ProviderCalls != 0 || proof.ExecutorCalls != 0 || f.models.Load() != 1 {
		t.Fatalf("host/fixture strict replay: %s %v %v", &out, err, jsonErr)
	}
	for _, index := range []int{6, 8} {
		bad := append([]string(nil), args...)
		bad[index] = "other"
		if index == 8 {
			bad[index] = "sha256:" + strings.Repeat("b", 64)
		}
		if err := sessionfixture.RunCLI(ctx, bad, io.Discard, io.Discard); err == nil {
			t.Fatal("changed original binding accepted")
		}
	}
	journal, err := sql.Open("sqlite", filepath.Join(scratch, "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	for _, record := range records {
		if approval := record.GetEvent().GetApprovalResult(); approval != nil {
			original, err := proto.Marshal(record.GetEvent())
			if err != nil {
				t.Fatal(err)
			}
			approval.Approved = false
			denied, err := proto.Marshal(record.GetEvent())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := journal.Exec("UPDATE events SET event=? WHERE session=? AND seq=?", denied, uid, record.GetSeq()); err != nil {
				t.Fatal(err)
			}
			out.Reset()
			if err := sessionfixture.RunCLI(ctx, args, &out, io.Discard); err == nil {
				t.Fatal("nonpositive approval qualified")
			}
			if err := json.Unmarshal(out.Bytes(), &proof); err != nil || proof.HeadHash != "" {
				t.Fatal("approval rejection reached replay hash validation")
			}
			if _, err := journal.Exec("UPDATE events SET event=? WHERE session=? AND seq=?", original, uid, record.GetSeq()); err != nil {
				t.Fatal(err)
			}
		}
	}
	durable, err := sql.Open("sqlite", filepath.Join(scratch, "publications.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	var artifact string
	if err := durable.QueryRow("SELECT artifact FROM publications").Scan(&artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := durable.Exec("UPDATE publications SET artifact='wrong'"); err != nil {
		t.Fatal(err)
	}
	if err := sessionfixture.RunCLI(ctx, args, io.Discard, io.Discard); err == nil {
		t.Fatal("changed artifact column qualified")
	}
	if _, err := durable.Exec("UPDATE publications SET artifact=?", artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := durable.Exec("UPDATE receipts SET output='{}'"); err != nil {
		t.Fatal(err)
	}
	if err := sessionfixture.RunCLI(ctx, args, io.Discard, io.Discard); err == nil {
		t.Fatal("damaged durable receipt qualified")
	}
}
