//go:build squadproof

package squadproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Catches DNS/nonlocal targets, ambiguous URL suffixes and unsafe SDK schemes.
func TestProofServerBoundary(t *testing.T) {
	for _, s := range []string{"127.0.0.1:8080", "http://127.0.0.1:8080/", "[::1]:8080", "http://[::1]:8080"} {
		got, err := proofServer(s)
		if err != nil || got == "" {
			t.Fatalf("valid server %q: %q %v", s, got, err)
		}
	}
	for _, s := range []string{"", "localhost:8080", "example.org:8080", "0.0.0.0:8080", "127.0.0.1:0", "https://127.0.0.1:80", "http://user@127.0.0.1:80", "http://127.0.0.1:80/?", "http://127.0.0.1:80/#", "http://127.0.0.1:80/a", "dns:///127.0.0.1:80"} {
		if _, err := proofServer(s); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe server %q: %v", s, err)
		}
	}
	if got, _ := proofServer("http://127.0.0.1:8080/"); got != "127.0.0.1:8080" {
		t.Fatal(got)
	}
}

// Catches options being accepted before validation and accidentally creating DBs.
func TestProofCommandsRejectUnsafeOptions(t *testing.T) {
	data := t.TempDir()
	for _, args := range [][]string{
		{"broker"}, {"scenario"}, {"inspect"}, {"replay"},
		{"broker", "--proof-only", "--data=" + data, "--server=localhost:80"},
		{"scenario", "--proof-only", "--data=" + data, "--server=127.0.0.1:80", "--case=fault"},
		{"inspect", "--proof-only", "--data=" + data},
		{"replay", "--proof-only", "--data=" + data},
		{"inspect", "--proof-only", "--writers-stopped", "--data=relative"},
		{"broker", "--proof-only", "--data=" + data, "--server=127.0.0.1:80", "--fault=crash"},
	} {
		if err := RunCLI(t.Context(), args, &bytes.Buffer{}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe command %v: %v", args, err)
		}
	}
	entries, err := os.ReadDir(data)
	if err != nil || len(entries) != 0 {
		t.Fatalf("invalid command mutated data: %v %v", entries, err)
	}
}

// Catches copying unsafe files, not isolating SQLite, and replaying partial state.
func TestDataSnapshotIsolation(t *testing.T) {
	l, path := openTestLedger(t)
	data := filepath.Dir(path)
	store, err := proofJournal(t.Context(), l, data)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = l.Admit(t.Context(), Operation{ID: "lead", Kind: "lead", Team: "proof-team", PackageDigest: proofDigest(), Member: "lead", Epoch: 1, Payload: []byte(`{"kind":"start"}`)}); err != nil {
		t.Fatal(err)
	}
	before := sourceDigests(t, data)
	if _, err = NewDataSnapshot(data, false); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	s, err := NewDataSnapshot(data, true)
	if err != nil {
		t.Fatal(err)
	}
	if !privateDirectory(s.Dir) || s.Dir == data {
		t.Fatal("snapshot not private and isolated")
	}
	s.Close()
	var output bytes.Buffer
	if err = RunCLI(t.Context(), []string{"inspect", "--proof-only", "--writers-stopped", "--data=" + data}, &output); err != nil {
		t.Fatal(err)
	}
	var p Proof
	if err = json.Unmarshal(output.Bytes(), &p); err != nil || p.Outcome != "inspected" || len(p.Operations) != 1 {
		t.Fatalf("inspect: %s %v", output.String(), err)
	}
	if err = RunCLI(t.Context(), []string{"replay", "--proof-only", "--writers-stopped", "--data=" + data}, &bytes.Buffer{}); !errors.Is(err, ErrHeld) {
		t.Fatalf("unmapped operation completed: %v", err)
	}
	if !reflect.DeepEqual(before, sourceDigests(t, data)) {
		t.Fatal("inspection changed original files")
	}
	if err = os.Symlink(path, filepath.Join(data, "journal.db-wal")); err != nil {
		t.Fatal(err)
	}
	if _, err = NewDataSnapshot(data, true); err == nil {
		t.Fatal("followed sidecar symlink")
	}
}

func sourceDigests(t *testing.T, data string) map[string][32]byte {
	t.Helper()
	out := map[string][32]byte{}
	for _, base := range []string{"proof.db", "journal.db"} {
		for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
			name := base + suffix
			b, err := os.ReadFile(filepath.Join(data, name))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			out[name] = sha256.Sum256(b)
		}
	}
	return out
}

// Real serving fixtures: no sleeps, readiness records are the synchronization.
func scenarioHost(t *testing.T, data string) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	var dones []chan error
	launch := func(args ...string) map[string]string {
		var b bytes.Buffer
		ready, done := make(chan struct{}, 1), make(chan error, 1)
		dones = append(dones, done)
		go func() { done <- RunCLI(ctx, args, readyWriter{&b, ready}) }()
		select {
		case <-ready:
		case err := <-done:
			t.Fatalf("startup %v: %v", args, err)
		}
		var record map[string]string
		if err := json.Unmarshal(b.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		return record
	}
	lead := launch("harness", "--proof-only", "--role=lead", "--addr=127.0.0.1:0")
	member := launch("harness", "--proof-only", "--role=member", "--addr=127.0.0.1:0")
	launch("executor", "--proof-only", "--data="+data)
	host := launch("host", "--proof-only", "--data="+data, "--addr=127.0.0.1:0", "--lead="+lead["address"], "--member="+member["address"])
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		for _, done := range dones {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(stop)
	return host["address"], stop
}

// Catches false completion, repeated dispatch on followups, incorrect queue order,
// implicit approvals, counter resets, and original journal recovery during replay.
func TestRunCaseRealHost(t *testing.T) {
	for _, name := range []string{"happy", "deny", "queue"} {
		t.Run(name, func(t *testing.T) {
			l, path := openTestLedger(t)
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			data := filepath.Dir(path)
			server, stop := scenarioHost(t, data)
			p, err := RunCase(t.Context(), name, data, "http://"+server+"/")
			if err != nil {
				t.Fatal(err)
			}
			if p.Outcome != "completed" || len(p.Operations) != 2 || p.Counters["rpc-create"] != 2 || p.Counters["model"] > 16 {
				t.Fatalf("proof: %+v", p)
			}
			wantEffects, wantExec := 1, 3
			if name == "deny" {
				wantEffects = 0
			}
			if name == "queue" {
				wantExec = 5
			}
			if p.Counts.Effects != wantEffects || p.Counters["rpc-exec"] != wantExec {
				t.Fatalf("effects/exec: %+v", p)
			}
			if name == "queue" {
				var kinds []string
				for _, in := range p.Inputs {
					if in.Target == "lead" {
						kinds = append(kinds, in.Kind)
					}
				}
				if !reflect.DeepEqual(kinds, []string{"user", "user", "result", "tick"}) {
					t.Fatalf("queue: %v", kinds)
				}
			}
			if _, err = RunCase(t.Context(), name, data, server); !errors.Is(err, ErrConflict) {
				t.Fatalf("nonfresh case: %v", err)
			}
			stop()
			before := sourceDigests(t, data)
			var b bytes.Buffer
			if err = RunCLI(t.Context(), []string{"replay", "--proof-only", "--writers-stopped", "--data=" + data}, &b); err != nil {
				t.Fatal(err)
			}
			var replay Proof
			if err = json.Unmarshal(b.Bytes(), &replay); err != nil || replay.Outcome != "replayed" || len(replay.Replays) != 2 {
				t.Fatalf("replay: %s %v", b.String(), err)
			}
			for _, r := range replay.Replays {
				if r.Models != 0 || r.Tools != 0 || len(r.Executions) == 0 || !reflect.DeepEqual(r.Executions, r.Covered) {
					t.Fatalf("coverage: %+v", r)
				}
			}
			if !reflect.DeepEqual(before, sourceDigests(t, data)) {
				t.Fatal("replay changed original")
			}
		})
	}
}
