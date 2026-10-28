package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/eventlog"
	"github.com/agent-primitives/sessions/harness/chatagent"
	"github.com/agent-primitives/sessions/sqlitelog"
)

type referenceUsageHarness struct{ chatagent.Harness }

func (h referenceUsageHarness) Run(ctx context.Context, start *api.Start, sink api.EventSink) error {
	if err := h.Harness.Run(ctx, start, sink); err != nil {
		return err
	}
	return sink.Usage(ctx, api.Usage{InputTokens: 12, OutputTokens: 4})
}

// Real SDK events, not fixture-injected version tags, must qualify. A legitimate
// delete marker remains valid Sessions data but not a qualifying execution tail.
func TestReferenceHostJournalSchema(t *testing.T) {
	for _, name := range []string{"native-zero", "usage-zero", "normal-one", "normal-two", "negative-version", "single-normal-one", "delete-marker-one"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(privateTestDir(t), "sessions.sqlite")
			file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			store, err := sqlitelog.Open((&url.URL{Scheme: "file", Path: path}).String())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			log := store.Session("candidate-session")
			c, err := controller.New(log, func(context.Context, api.ModelRequest) (api.ModelResponse, error) {
				return api.ModelResponse{Message: *api.TextMessage("assistant", "hello world")}, nil
			}, controller.WithSessionUID("candidate-session"))
			if err != nil {
				t.Fatal(err)
			}
			var h api.Harness = chatagent.Harness{Model: "model"}
			if name == "usage-zero" {
				h = referenceUsageHarness{chatagent.Harness{Model: "model"}}
			}
			if err := c.Exec(t.Context(), h, []api.Message{*api.TextMessage("user", "question")}, 0); err != nil {
				t.Fatal(err)
			}
			if name == "delete-marker-one" {
				if _, err := store.DeleteSession(t.Context(), "candidate-session"); err != nil {
					t.Fatal(err)
				}
			}
			records, err := log.Read(1)
			if err != nil {
				t.Fatal(err)
			}
			if err := log.Verify(); err != nil {
				t.Fatalf("actual SDK journal invalid: %v", err)
			}
			for i, rec := range records {
				if name == "delete-marker-one" && i == len(records)-1 {
					if rec.Event.SchemaVersion != 1 || rec.Event.Kind != api.EventLifecycle || rec.Event.Lifecycle.Kind != api.LifecycleDelete {
						t.Fatal("LOG-4 deletion exception missing")
					}
				} else if rec.Event.SchemaVersion != 0 {
					t.Fatal("native producer no longer leaves tag unset")
				}
			}
			if name == "normal-one" || name == "normal-two" || name == "negative-version" || name == "single-normal-one" {
				// Rehash before retention so rejection is about the fabricated tag,
				// not an unrelated hash-chain failure.
				copy := eventlog.New()
				for i, rec := range records {
					ev := rec.Event
					switch name {
					case "normal-one":
						ev.SchemaVersion = 1
					case "normal-two":
						ev.SchemaVersion = 2
					case "negative-version":
						ev.SchemaVersion = -1
					case "single-normal-one":
						if i == 2 {
							ev.SchemaVersion = 1
						}
					}
					if _, err := copy.Append(int64(i), 0, ev); err != nil {
						t.Fatal(err)
					}
				}
				records = copy.Snapshot()
			}
			if err := eventlog.VerifyChain("", records); err != nil {
				t.Fatal(err)
			}
			s, _ := testStore(t)
			plan := testPlan()
			l := begin(t, s, plan)
			b, err := json.Marshal(records)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := s.retain(b)
			if err != nil {
				t.Fatal(err)
			}
			j := Journal{SessionID: "candidate-session", ExecutionID: records[0].Event.ExecutionID, HeadHash: records[len(records)-1].Hash, Count: len(records), Blob: ref}
			got, err := s.complete(t.Context(), l, []Observation{{CaseID: "case", Run: 1, Candidate: j}})
			want := Incomplete
			if name == "native-zero" || name == "usage-zero" {
				want = Passed
			}
			if err != nil || got.State != want {
				t.Fatalf("state=%s want=%s: %v", got.State, want, err)
			}
			_, err = s.VerifyForActivation(t.Context(), got.ID, plan, time.Now())
			if (err == nil) != (want == Passed) {
				t.Fatalf("eligibility disagrees with original evidence: %v", err)
			}
			after, err := s.blob(ref)
			if err != nil || !bytes.Equal(after, b) {
				t.Fatal("verifier rewrote original journal")
			}
		})
	}
}
