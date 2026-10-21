package targetversions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedIntegrity(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected refusal")
	}
	if !errors.Is(err, ErrIntegrity) || err.Error() != ErrIntegrity.Error() {
		t.Errorf("refusal must be fixed integrity message, got %q", err)
	}
}

func TestRefusalPrivacy(t *testing.T) {
	const marker = "SYNTHETIC-CREDENTIAL-NOT-A-REAL-TOKEN"
	for _, api := range []string{"ReadOperation", "StartAbort", "Verify", "Open"} {
		t.Run(api, func(t *testing.T) {
			s, p := newStore(t)
			o := begin(t, s, request(register(t, s, "agent"), "a"))
			var err error
			switch api {
			case "ReadOperation", "StartAbort":
				_, err = s.db.Exec("UPDATE operation_state SET data=json_set(data,'$.ReservedAt',?) WHERE id=?", marker, o.ID)
			case "Verify", "Open":
				_, err = s.db.Exec("UPDATE events SET data=json_set(data,'$.At',?) WHERE target=? AND sequence=2", marker, "agent")
			}
			if err != nil {
				t.Fatal(err)
			}
			switch api {
			case "ReadOperation":
				_, err = s.ReadOperation(ctx, o.ID)
			case "StartAbort":
				_, err = s.StartAbort(ctx, step(o), "cancel")
			case "Verify":
				err = s.Verify(ctx)
			case "Open":
				id := s.ID
				if err = s.Close(); err != nil {
					t.Fatal(err)
				}
				var reopened *Store
				reopened, err = Open(p, id)
				if reopened != nil {
					defer reopened.Close()
				}
			}
			fixedIntegrity(t, err)
			if err != nil && strings.Contains(err.Error(), marker) {
				t.Error("stored synthetic credential was copied to refusal")
			}
		})
	}
	t.Run("ReadTargetNumericIdentity", func(t *testing.T) {
		s, _ := newStore(t)
		register(t, s, "agent")
		const numericMarker = "9876543210987654321098765432109876543210"
		if _, err := s.db.Exec("UPDATE targets SET data=? WHERE id=?", `{"Generation":`+numericMarker+`}`, "agent"); err != nil {
			t.Fatal(err)
		}
		_, err := s.ReadTarget(ctx, "agent")
		fixedIntegrity(t, err)
		if err != nil && strings.Contains(err.Error(), numericMarker) {
			t.Error("stored synthetic numeric identity was copied to refusal")
		}
	})
	t.Run("PrivateDirectoryCreation", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "no-write")
		if err := os.Mkdir(base, 0500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(base, 0700)
		path := filepath.Join(base, marker, "versions.db")
		s, err := Create(path)
		if s != nil {
			defer s.Close()
		}
		fixedIntegrity(t, err)
		if err != nil && strings.Contains(err.Error(), marker) {
			t.Error("private path component was copied to refusal")
		}
	})
}

func TestTransactionRefusalsAreFixed(t *testing.T) {
	for _, want := range []error{ErrInvalid, ErrConflict, ErrBusy, ErrIntegrity, ErrUnsupported, context.Canceled, context.DeadlineExceeded} {
		t.Run(want.Error(), func(t *testing.T) {
			s, _ := newStore(t)
			err := s.transact(ctx, func(query) error { return fmt.Errorf("%w: private diagnostic", want) })
			if err != want {
				t.Fatalf("refusal retains diagnostic or loses class: got %v, want %v", err, want)
			}
		})
	}
}

func TestClosedStoreRefusalsAreFixed(t *testing.T) {
	for _, api := range []string{"RegisterTarget", "Begin", "ReadTarget", "ReadOperation", "History", "Verify", "StartAbort"} {
		t.Run(api, func(t *testing.T) {
			s, _ := newStore(t)
			r := request(register(t, s, "agent"), "a")
			o := begin(t, s, r)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			var err error
			switch api {
			case "RegisterTarget":
				_, err = s.RegisterTarget(ctx, "other")
			case "Begin":
				_, err = s.Begin(ctx, r)
			case "ReadTarget":
				_, err = s.ReadTarget(ctx, "agent")
			case "ReadOperation":
				_, err = s.ReadOperation(ctx, o.ID)
			case "History":
				_, err = s.History(ctx, "agent", 0, 100)
			case "Verify":
				err = s.Verify(ctx)
			case "StartAbort":
				_, err = s.StartAbort(ctx, step(o), "cancel")
			}
			fixedIntegrity(t, err)
		})
	}
}

func TestBusyRefusalIsFixed(t *testing.T) {
	s, p := newStore(t)
	other, err := Open(p, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err = other.db.Exec("PRAGMA busy_timeout=0"); err != nil {
		t.Fatal(err)
	}
	if err = s.transact(ctx, func(query) error {
		if got := other.Verify(ctx); got != ErrBusy {
			t.Errorf("busy refusal retains diagnostic or loses class: %v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if other.bad.Load() {
		t.Fatal("busy verification latched corruption")
	}
}

func TestStepGenerationAndRevision(t *testing.T) {
	for _, field := range []string{"generation", "revision"} {
		t.Run(field, func(t *testing.T) {
			s, _ := newStore(t)
			o := begin(t, s, request(register(t, s, "agent"), "a"))
			stale := step(o)
			if field == "generation" {
				stale.Generation++
			} else {
				stale.ExpectedRevision++
			}
			if _, err := s.MarkPrepared(ctx, stale, receipt(s, o, "prepared")); !errors.Is(err, ErrConflict) {
				t.Fatalf("wrong %s step accepted or misclassified: %v", field, err)
			}
			got, err := s.ReadOperation(ctx, o.ID)
			if err != nil || !same(got, o) {
				t.Fatal("refused callback changed state", err)
			}
		})
	}
}

func TestRollbackSourceMustBeCommitted(t *testing.T) {
	s, _ := newStore(t)
	committed(t, s, begin(t, s, request(register(t, s, "agent"), "first")))
	candidate := begin(t, s, activeRequest(t, s, "agent", "uncommitted"))
	v, err := s.StartAbort(ctx, step(candidate), "cancel")
	candidate = must(t, v, err)
	v, err = s.FinishAbort(ctx, step(candidate), receipt(s, candidate, "release"), false)
	candidate = must(t, v, err)
	r := activeRequest(t, s, "agent", "rollback")
	r.Intent = "rollback"
	r.SourceVersionID = candidate.Version.ID
	r.Candidate = candidate.Version.Candidate
	r.Candidate.Qualification.ID = "fresh-rollback"
	r.DecisionRecord.Request.Action = "rollback"
	r.DecisionRecord.Authorization.Action = "rollback"
	if _, err = s.Begin(ctx, r); !errors.Is(err, ErrConflict) {
		t.Fatalf("aborted candidate treated as committed rollback source: %v", err)
	}
}

func TestExactSchemaRequired(t *testing.T) {
	for _, stmt := range []string{"CREATE TABLE unexpected (id TEXT)", "ALTER TABLE targets ADD COLUMN unexpected TEXT"} {
		t.Run(strings.Fields(stmt)[0], func(t *testing.T) {
			s, p := newStore(t)
			register(t, s, "agent")
			if _, err := s.db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			id := s.ID
			s.Close()
			got, err := Open(p, id)
			if got != nil {
				defer got.Close()
			}
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("modified schema accepted: %v", err)
			}
		})
	}
}

func TestFutureAuthorityRefused(t *testing.T) {
	s, _ := newStore(t)
	o := prepared(t, s, begin(t, s, request(register(t, s, "agent"), "a")))
	a := authority(s, o)
	a.AuthorizedAt = s.now().Add(time.Hour)
	if _, err := s.Reserve(ctx, step(o), a); !errors.Is(err, ErrConflict) {
		t.Fatalf("future authority accepted: %v", err)
	}
}

func TestQualificationEligibilityRequired(t *testing.T) {
	for _, flag := range []string{"Complete", "Passed", "Eligible"} {
		t.Run(flag, func(t *testing.T) {
			s, _ := newStore(t)
			r := request(register(t, s, "agent"), "a")
			switch flag {
			case "Complete":
				r.Candidate.Qualification.Complete = false
			case "Passed":
				r.Candidate.Qualification.Passed = false
			case "Eligible":
				r.Candidate.Qualification.Eligible = false
			}
			if _, err := s.Begin(ctx, r); !errors.Is(err, ErrInvalid) {
				t.Fatalf("qualification %s=false accepted: %v", flag, err)
			}
		})
	}
}
