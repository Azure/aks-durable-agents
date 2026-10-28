package agentcontroller

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/eventlog"
)

func executionFor(t *testing.T, f *executionFixture) *CandidateExecutor {
	t.Helper()
	x, err := NewCandidateExecutor(f.pkg, f.expected, f.config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.Close() })
	return x
}

func TestCandidateExecutorOrderedIsolation(t *testing.T) {
	f := newExecutionFixture(t, nil)
	x := executionFor(t, f)
	live := eventlog.New()
	if _, err := live.Append(0, 0, api.Event{Kind: api.EventInput, Message: api.TextMessage("user", "live history")}); err != nil {
		t.Fatal(err)
	}
	liveHead := live.Snapshot()[0].Hash
	liveDir := t.TempDir()
	marker := filepath.Join(liveDir, "serving-socket.marker")
	if err := os.WriteFile(marker, []byte("live"), 0600); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, call := range x.Calls() {
		got, err := x.Execute(t.Context(), call.SlotID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Call != call || seen[got.SessionID] || seen[got.ExecutionID] {
			t.Fatal("case/repetition identity reused")
		}
		seen[got.SessionID], seen[got.ExecutionID] = true, true
	}
	if f.sends.Load() != 4 || f.journals.Load() != 4 || !bytes.Equal(f.bodies[0], f.bodies[1]) || !bytes.Equal(f.bodies[1], f.bodies[2]) || bytes.Equal(f.bodies[2], f.bodies[3]) {
		t.Fatal("repetitions were omitted, nonced or leaked history")
	}
	cfg := f.budget.Config
	cfg.RunID = "record-two"
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg.LedgerPath = filepath.Join(dir, "run.sqlite")
	p, err := modeltransport.OpenRunPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	config := f.config
	config.RunID, config.Policy = cfg.RunID, p
	other, err := NewCandidateExecutor(f.pkg, f.expected, config)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	got, err := other.Execute(t.Context(), f.budget.Calls[0].SlotID)
	if err != nil || seen[got.SessionID] || !bytes.Equal(f.bodies[0], f.bodies[4]) {
		t.Fatalf("run scope was not isolated: %v", err)
	}
	entries, err := os.ReadDir(liveDir)
	b, readErr := os.ReadFile(marker)
	if err != nil || readErr != nil || len(entries) != 1 || string(b) != "live" || live.Head() != 1 || live.Snapshot()[0].Hash != liveHead {
		t.Fatal("live state changed")
	}
}

type executionLog struct {
	eventlog.Store
	fences      atomic.Int64
	read        func() error
	head        func() (int64, error)
	appendEvent func(api.Event)
}

func (l *executionLog) Head() (int64, error) {
	if l.head != nil {
		return l.head()
	}
	return l.Store.Head()
}
func (l *executionLog) NewFence() (int64, error) { l.fences.Add(1); return l.Store.NewFence() }
func (l *executionLog) Read(seq int64) ([]eventlog.Record, error) {
	if l.read != nil {
		if err := l.read(); err != nil {
			return nil, err
		}
	}
	return l.Store.Read(seq)
}
func (l *executionLog) Append(head, fence int64, ev api.Event) (eventlog.Record, error) {
	if l.appendEvent != nil {
		l.appendEvent(ev)
	}
	return l.Store.Append(head, fence, ev)
}
func (l *executionLog) CheckWritable() error { return eventlog.CheckWritable(l.Store) }

func TestCandidateExecutorRefusesReuse(t *testing.T) {
	for _, name := range []string{"unknown", "order", "duplicate", "nonempty", "independent-executor"} {
		t.Run(name, func(t *testing.T) {
			f := newExecutionFixture(t, nil)
			var existing *executionLog
			if name == "nonempty" {
				log := eventlog.New()
				if _, err := log.Append(0, 0, api.Event{Kind: api.EventInput, Message: api.TextMessage("user", "live")}); err != nil {
					t.Fatal(err)
				}
				existing = &executionLog{Store: eventlog.AsStore(log)}
				f.config.Journal = func(string) (eventlog.Store, error) { f.journals.Add(1); return existing, nil }
			}
			if name == "independent-executor" {
				// Fresh independent logs force the persistent policy, not Head>0,
				// to prevent another send of the same semantic slot.
				f.config.Journal = func(string) (eventlog.Store, error) { f.journals.Add(1); return eventlog.AsStore(eventlog.New()), nil }
			}
			x := executionFor(t, f)
			slot := f.budget.Calls[0].SlotID
			wantSends, wantJournals := int64(0), int64(0)
			switch name {
			case "unknown":
				slot = "unknown"
			case "order":
				slot = f.budget.Calls[1].SlotID
			case "duplicate", "independent-executor":
				if _, err := x.Execute(t.Context(), slot); err != nil {
					t.Fatal(err)
				}
				wantSends, wantJournals = 1, 1
				if name == "independent-executor" {
					x = executionFor(t, f)
					wantJournals = 2
				}
			case "nonempty":
				wantJournals = 1
			}
			if _, err := x.Execute(t.Context(), slot); err == nil {
				t.Fatal("reuse/order accepted")
			}
			if f.sends.Load() != wantSends || f.journals.Load() != wantJournals {
				t.Fatal("refusal caused forbidden effects")
			}
			if existing != nil {
				head, _ := existing.Head()
				if existing.fences.Load() != 0 || head != 1 {
					t.Fatal("nonempty log was fenced or changed")
				}
			}
		})
	}
}

func TestCandidateExecutorFailureStopsRun(t *testing.T) {
	for _, name := range []string{"provider", "unknown", "readback", "factory", "head", "nil-log"} {
		t.Run(name, func(t *testing.T) {
			var handler http.HandlerFunc
			if name == "provider" {
				handler = func(w http.ResponseWriter, _ *http.Request) {
					http.Error(w, "fixture failure", http.StatusServiceUnavailable)
				}
			}
			if name == "unknown" {
				handler = func(w http.ResponseWriter, _ *http.Request) {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close() // Provider received input; its outcome was lost.
				}
			}
			f := newExecutionFixture(t, handler)
			base := f.config.Journal
			f.config.Journal = func(uid string) (eventlog.Store, error) {
				if name == "factory" {
					f.journals.Add(1)
					return nil, errors.New("fixture factory")
				}
				if name == "nil-log" {
					f.journals.Add(1)
					return nil, nil
				}
				log, err := base(uid)
				if name == "head" {
					return &executionLog{Store: log, head: func() (int64, error) { return 0, errors.New("fixture head") }}, nil
				}
				if name == "readback" {
					return &executionLog{Store: log, read: func() error {
						if f.sends.Load() > 0 {
							return errors.New("fixture readback")
						}
						return nil
					}}, err
				}
				return log, err
			}
			x := executionFor(t, f)
			if _, err := x.Execute(t.Context(), f.budget.Calls[0].SlotID); err == nil {
				t.Fatal("mechanical failure accepted")
			}
			sends, journals := f.sends.Load(), f.journals.Load()
			if _, err := x.Execute(t.Context(), f.budget.Calls[1].SlotID); err == nil {
				t.Fatal("run continued after mechanical failure")
			}
			if f.sends.Load() != sends || f.journals.Load() != journals {
				t.Fatal("failed run performed later work")
			}
			if name == "provider" {
				for _, log := range f.logs {
					recs, err := log.Read(1)
					if err != nil || len(recs) != 4 || recs[3].Event.Kind != api.EventError || eventlog.VerifyChain("", recs) != nil {
						t.Fatal("original ERROR tail was discarded or changed")
					}
				}
			}
		})
	}
}

// Completed assertion misses belong to qualification, not execution control.
func TestCandidateExecutorWrongAnswersContinue(t *testing.T) {
	f := newExecutionFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"wrong\"},\"finish_reason\":\"stop\"}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":4}}\n\ndata: [DONE]\n\n")
	})
	x := executionFor(t, f)
	for _, call := range x.Calls() {
		got, err := x.Execute(t.Context(), call.SlotID)
		if err != nil || got.Records[3].Event.Message.Parts[0].Text.Text != "wrong" {
			t.Fatalf("assertion miss stopped execution: %v", err)
		}
	}
	if f.sends.Load() != 4 {
		t.Fatal("suite omitted repetitions after wrong answer")
	}
}

func TestCandidateExecutorCancelClose(t *testing.T) {
	t.Run("before-dispatch", func(t *testing.T) {
		f := newExecutionFixture(t, nil)
		x := executionFor(t, f)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := x.Execute(ctx, f.budget.Calls[0].SlotID); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
		if _, err := x.Execute(t.Context(), f.budget.Calls[0].SlotID); err == nil {
			t.Fatal("cancelled executor retried")
		}
		if f.sends.Load() != 0 || f.journals.Load() != 0 {
			t.Fatal("cancelled run touched journal/provider")
		}
	})
	t.Run("close-before-dispatch", func(t *testing.T) {
		f := newExecutionFixture(t, nil)
		x := executionFor(t, f)
		if err := x.Close(); err != nil {
			t.Fatal(err)
		}
		if err := x.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := x.Execute(t.Context(), f.budget.Calls[0].SlotID); err == nil || f.journals.Load() != 0 || f.sends.Load() != 0 {
			t.Fatal("closed executor dispatched")
		}
		// Policy/storage ownership stays with the caller.
		other := executionFor(t, f)
		if _, err := other.Execute(t.Context(), f.budget.Calls[0].SlotID); err != nil {
			t.Fatalf("Close shut down caller policy: %v", err)
		}
	})
	t.Run("active-close-drains", func(t *testing.T) {
		entered, errorAppend, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		f := newExecutionFixture(t, func(_ http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() })
		base := f.config.Journal
		var callbacks atomic.Int64
		f.config.Journal = func(uid string) (eventlog.Store, error) {
			if callbacks.Add(1) > 1 {
				return nil, errors.New("forbidden concurrent journal")
			}
			log, err := base(uid)
			return &executionLog{Store: log, appendEvent: func(ev api.Event) {
				if ev.Kind == api.EventError {
					close(errorAppend)
					<-release
				}
			}}, err
		}
		x := executionFor(t, f)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		executed := make(chan error, 1)
		go func() { _, err := x.Execute(ctx, f.budget.Calls[0].SlotID); executed <- err }()
		<-entered
		if _, err := x.Execute(t.Context(), f.budget.Calls[1].SlotID); err == nil {
			t.Error("concurrent execution accepted")
		}
		closed := make(chan error, 1)
		go func() { closed <- x.Close() }()
		select {
		case <-errorAppend:
		case <-time.After(2 * time.Second):
			t.Error("Close did not cancel active request")
			cancel()
			<-errorAppend
		}
		select {
		case <-closed:
			t.Error("Close returned before active journal append drained")
			closed = nil
		default:
		}
		close(release)
		if err := <-executed; !errors.Is(err, context.Canceled) {
			t.Errorf("active result: %v", err)
		}
		if closed != nil {
			if err := <-closed; err != nil {
				t.Error(err)
			}
		}
		if callbacks.Load() != 1 || f.sends.Load() != 1 {
			t.Error("concurrent refusal performed effects")
		}
		if _, err := x.Execute(t.Context(), f.budget.Calls[1].SlotID); err == nil {
			t.Error("closed run advanced")
		}
	})
}
