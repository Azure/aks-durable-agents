package targetversions

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestFailedRollbackRecoveryUsesCurrentPredecessor(t *testing.T) {
	s, _ := newStore(t)
	first := committed(t, s, begin(t, s, request(register(t, s, "agent"), "one")))
	r := activeRequest(t, s, "agent", "two")
	r.Candidate.Artifact.SuiteDigest = strings.Repeat("b", 64)
	r.Candidate.SourceDigest = strings.Repeat("b", 64)
	r.Candidate.Qualification.Artifact = r.Candidate.Artifact
	second := committed(t, s, begin(t, s, r))
	r = activeRequest(t, s, "agent", "rollback-fails")
	r.Intent = "rollback"
	r.SourceVersionID = first.Version.ID
	r.Candidate = clone(first.Version.Candidate)
	r.DecisionRecord.Request.Action = "rollback"
	r.DecisionRecord.Authorization.Action = "rollback"
	o := reserved(t, s, prepared(t, s, begin(t, s, r)))
	o = abandonFinish(t, s, abandonStart(t, s, o, "abandon-rollback"))
	recover := recoveryRequest(t, s, o, "recover-current")
	if recover.SourceVersionID != second.Version.ID || recover.Candidate.Artifact.SuiteDigest != strings.Repeat("b", 64) {
		t.Fatal("recovery used rollback candidate instead of current predecessor")
	}
	committed(t, s, begin(t, s, recover))
}
func TestHistoryReadOnlyAndPagination(t *testing.T) {
	s, _ := newStore(t)
	_, o := pendingWithPredecessor(t, s)
	o = abandonFinish(t, s, abandonStart(t, s, o, "abandon"))
	committed(t, s, begin(t, s, recoveryRequest(t, s, o, "recover")))
	before, e := s.ReadTarget(ctx, "agent")
	before = must(t, before, e)
	var after uint64
	var events []Event
	for {
		page, e := s.History(ctx, "agent", after, 2)
		if e != nil {
			t.Fatal(e)
		}
		if len(page) > 2 {
			t.Fatal("unbounded page")
		}
		if len(page) == 0 {
			break
		}
		for _, ev := range page {
			if ev.Sequence != after+1 {
				t.Fatal("unordered", ev.Sequence, after)
			}
			after = ev.Sequence
			events = append(events, ev)
		}
	}
	if len(events) != int(before.Revision) {
		t.Fatal("lost history")
	}
	for _, limit := range []int{-1, 0, 1000} {
		page, e := s.History(ctx, "agent", 0, limit)
		if e != nil || len(page) > 100 {
			t.Fatal("bad page bound", e, len(page))
		}
	}
	seen := map[Link]bool{}
	for _, ev := range events {
		for _, l := range ev.Links {
			seen[l] = true
		}
	}
	for l := range seen {
		if strings.HasSuffix(l.Kind, "_reverse") {
			continue
		}
		if !seen[Link{l.Kind + "_reverse", l.ToID, l.FromID}] {
			t.Fatal("missing reciprocal", l)
		}
	}
	if e = s.Verify(ctx); e != nil {
		t.Fatal(e)
	}
	got, e := s.ReadTarget(ctx, "agent")
	if e != nil || got != before {
		t.Fatal("read mutated projection", e)
	}
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = s.History(c, "agent", 0, 1); !errors.Is(e, context.Canceled) {
		t.Fatal("cancel not propagated", e)
	}
}
func TestLocalRestoreIntegrity(t *testing.T) {
	for _, damage := range []string{"link", "reverse", "projection", "event", "version", "operation", "tombstone", "key", "decision", "qualification", "abandonment", "backend", "future", "truncated"} {
		t.Run(damage, func(t *testing.T) {
			s, p := newStore(t)
			_, o := pendingWithPredecessor(t, s)
			o = abandonFinish(t, s, abandonStart(t, s, o, "abandon"))
			committed(t, s, begin(t, s, recoveryRequest(t, s, o, "recover")))
			id := s.ID
			s.Close()
			db, e := sql.Open("sqlite", p)
			if e != nil {
				t.Fatal(e)
			}
			statements := map[string]string{"link": "DELETE FROM links WHERE kind='source'", "reverse": "DELETE FROM links WHERE kind='source_reverse'", "projection": "UPDATE targets SET data=json_set(data,'$.Availability','ready','$.ActiveVersionID','absent')", "event": "DELETE FROM events WHERE sequence=2", "version": "UPDATE versions SET data=json_set(data,'$.ExecutionContextID','other')", "operation": "UPDATE operations SET data=json_set(data,'$.Request.Key','changed')", "tombstone": "DELETE FROM tombstones", "key": "DELETE FROM request_keys WHERE kind='abandon'", "decision": "DELETE FROM decision_claims WHERE kind='begin'", "qualification": "UPDATE qualifications SET data=json_set(data,'$.Digest','bad')", "abandonment": "DELETE FROM abandonments", "backend": "UPDATE metadata SET backend_id='other'", "future": "UPDATE metadata SET schema_version=2"}
			if damage != "truncated" {
				if _, e = db.Exec(statements[damage]); e != nil {
					t.Fatal(e)
				}
			}
			db.Close()
			if damage == "truncated" {
				if e = os.Truncate(p, 17); e != nil {
					t.Fatal(e)
				}
			}
			before, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			_, e = Open(p, id)
			want := ErrIntegrity
			if damage == "future" {
				want = ErrUnsupported
			}
			if !errors.Is(e, want) {
				t.Fatalf("damaged %s opened: %v", damage, e)
			}
			after, e := os.ReadFile(p)
			if e != nil || string(after) != string(before) {
				t.Fatal("failed Open rewrote database", e)
			}
		})
	}
	t.Run("live verification fails closed", func(t *testing.T) {
		s, _ := newStore(t)
		register(t, s, "agent")
		if _, e := s.db.Exec("UPDATE targets SET data=json_set(data,'$.Availability','ready')"); e != nil {
			t.Fatal(e)
		}
		if e := s.Verify(ctx); !errors.Is(e, ErrIntegrity) {
			t.Fatal(e)
		}
		if _, e := s.RegisterTarget(ctx, "other"); !errors.Is(e, ErrIntegrity) {
			t.Fatal("verified corruption allowed mutation", e)
		}
	})
}

type helperProcess struct {
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	cancel context.CancelFunc
}

func startHelper(t *testing.T, p, id string, o Operation, action string) *helperProcess {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	c, cancel := context.WithTimeout(ctx, 45*time.Second)
	cmd := exec.CommandContext(c, exe, "-test.run=^TestProcessHelper$")
	b, _ := json.Marshal(o)
	cmd.Env = append(os.Environ(), "TARGETVERSIONS_HELPER="+action, "TARGETVERSIONS_PATH="+p, "TARGETVERSIONS_ID="+id, "TARGETVERSIONS_OP="+string(b))
	in, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stderr = os.Stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	h := &helperProcess{cmd, in, bufio.NewReader(out), cancel}
	t.Cleanup(func() { cancel(); in.Close() })
	ready, e := h.out.ReadString('\n')
	if e != nil || ready != "READY\n" {
		t.Fatal("helper readiness", ready, e)
	}
	return h
}
func (h *helperProcess) release(t *testing.T) {
	t.Helper()
	if _, e := io.WriteString(h.in, "go\n"); e != nil {
		t.Fatal(e)
	}
	h.in.Close()
}
func (h *helperProcess) result(t *testing.T) string {
	t.Helper()
	b, e := io.ReadAll(h.out)
	if e != nil {
		t.Fatal(e)
	}
	if e = h.cmd.Wait(); e != nil {
		t.Fatal(e, string(b))
	}
	h.cancel()
	return strings.TrimSpace(string(b))
}
func TestCrossProcessCAS(t *testing.T) {
	for _, phase := range []string{"reserve-abort", "commit-abandon"} {
		t.Run(phase, func(t *testing.T) {
			s, p := newStore(t)
			_, o := pendingWithPredecessor(t, s)
			a, b := "commit", "abandon"
			if phase == "reserve-abort" {
				o = begin(t, s, request(register(t, s, "fresh"), "a"))
				o = prepared(t, s, o)
				a, b = "reserve", "abort"
			} else {
				o = retired(t, s, o)
			}
			one := startHelper(t, p, s.ID, o, a)
			two := startHelper(t, p, s.ID, o, b)
			one.release(t)
			two.release(t)
			x, y := one.result(t), two.result(t)
			if (x == "WIN") == (y == "WIN") || (x != "WIN" && x != "CONFLICT") || (y != "WIN" && y != "CONFLICT") {
				t.Fatal("process arbitration", x, y)
			}
			if e := s.Verify(ctx); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestCrashPhaseReadBack(t *testing.T) {
	for _, action := range []string{"prepare", "reserve", "retire", "commit", "abort", "finish-abort", "abandon", "finish-abandon"} {
		t.Run(action, func(t *testing.T) {
			s, p := newStore(t)
			o := begin(t, s, request(register(t, s, "agent"), "a"))
			want := "prepared"
			switch action {
			case "reserve":
				o = prepared(t, s, o)
				want = "reserved"
			case "retire":
				o = reserved(t, s, prepared(t, s, o))
				want = "predecessor-retired"
			case "commit":
				o = retired(t, s, reserved(t, s, prepared(t, s, o)))
				want = "committed"
			case "abort":
				want = "aborting"
			case "finish-abort":
				v, e := s.StartAbort(ctx, step(o), "cancel")
				o = must(t, v, e)
				want = "aborted"
			case "abandon":
				o = reserved(t, s, prepared(t, s, o))
				want = "abandoning"
			case "finish-abandon":
				o = abandonStart(t, s, reserved(t, s, prepared(t, s, o)), "abandon")
				want = "abandoned-unavailable"
			}
			before := startHelper(t, p, s.ID, o, "crash-before")
			before.release(t)
			before.result(t)
			s = reopen(t, s, p)
			got, e := s.ReadOperation(ctx, o.ID)
			if e != nil || !same(o, got) {
				t.Fatal("uncommitted work survived", e)
			}
			after := startHelper(t, p, s.ID, o, action)
			after.release(t)
			if result := after.result(t); result != "WIN" {
				t.Fatal(result)
			}
			s = reopen(t, s, p)
			got, e = s.ReadOperation(ctx, o.ID)
			if e != nil || got.Phase != want || got.Revision != o.Revision+1 {
				t.Fatal("durable phase lost", e, got.Phase, want)
			}
			if e = s.Verify(ctx); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestProcessHelper(t *testing.T) {
	action := os.Getenv("TARGETVERSIONS_HELPER")
	if action == "" {
		return
	}
	s, e := Open(os.Getenv("TARGETVERSIONS_PATH"), os.Getenv("TARGETVERSIONS_ID"))
	if e != nil {
		t.Fatal(e)
	}
	var o Operation
	if e = json.Unmarshal([]byte(os.Getenv("TARGETVERSIONS_OP")), &o); e != nil {
		t.Fatal(e)
	}
	fmt.Println("READY")
	if _, e = bufio.NewReader(os.Stdin).ReadString('\n'); e != nil {
		t.Fatal(e)
	}
	switch action {
	case "crash-before":
		c, e := s.db.Conn(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = c.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
			t.Fatal(e)
		}
		if _, e = c.ExecContext(ctx, "UPDATE targets SET data='null' WHERE id=?", o.Request.TargetID); e != nil {
			t.Fatal(e)
		}
		os.Exit(0)
	case "prepare":
		_, e = s.MarkPrepared(ctx, step(o), receipt(s, o, "prepared"))
	case "reserve":
		_, e = s.Reserve(ctx, step(o), authority(s, o))
	case "retire":
		_, e = s.MarkRetired(ctx, step(o), receipt(s, o, "no_source"))
	case "commit":
		_, e = s.Commit(ctx, step(o), receipt(s, o, "commit"))
	case "abort":
		_, e = s.StartAbort(ctx, step(o), "cancel")
	case "finish-abort":
		_, e = s.FinishAbort(ctx, step(o), receipt(s, o, "release"), false)
	case "abandon":
		_, e = s.StartAbandon(ctx, abandonRequest(s, o, "abandon"))
	case "finish-abandon":
		p, n := abandonReceipts(s, o)
		_, e = s.FinishAbandon(ctx, step(o), p, n)
	default:
		t.Fatal("unknown helper action")
	}
	if e == nil {
		fmt.Println("WIN")
	} else if errors.Is(e, ErrConflict) {
		fmt.Println("CONFLICT")
	} else {
		t.Fatal(e)
	}
	os.Exit(0)
}
