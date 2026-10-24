package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestStoreScopeProjectionIntegrity(t *testing.T) {
	s, _ := testStore(t)
	r := admit(t, s)
	if _, err := s.db.Exec("UPDATE records SET workspace='foreign' WHERE id=?", r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(context.Background(), r.ID); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("changed scope projection accepted: %v", err)
	}
}
func TestAdmissionMaxMetadata(t *testing.T) {
	s, _ := testStore(t)
	p := testPlan()
	p.Cases[0].Runs = 64
	p.Cases[0].MinPasses = 1
	r, err := s.Admit(context.Background(), Request{Key: "key", Requester: "caller", Plan: p})
	if err != nil {
		t.Fatal(err)
	}
	obs := make([]Observation, 64)
	for i := range obs {
		session := strings.Repeat("s", 125) + fmt.Sprintf("%03d", i)
		execution := strings.Repeat("e", 125) + fmt.Sprintf("%03d", i)
		// This test isolates the metadata budget, not 64 repetitions of the
		// separately tested filesystem sync and journal verifier.
		obs[i] = Observation{CaseID: "case", Run: i + 1, Candidate: Journal{SessionID: session, ExecutionID: execution, HeadHash: strings.Repeat("f", 64), Count: 6, Blob: BlobRef{Digest: digest("6"), Size: maxBlobBytes}}}
	}
	r.Observations = obs
	r.State = Passed
	r.Generation = 1
	r.CompletedAt = time.Now().UTC()
	seal(&r)
	b, err := json.Marshal(r)
	if err != nil || len(b) > maxRecordBytes {
		t.Fatalf("admitted metadata cannot fit: %d %v", len(b), err)
	}
	p.Cases[0].Runs = 65
	if _, err = s.Admit(context.Background(), Request{Key: "oversize", Requester: "caller", Plan: p}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversize admitted: %v", err)
	}
}
func TestStaleGenerationWhileRunning(t *testing.T) {
	s, _ := testStore(t)
	l := begin(t, s, testPlan())
	r, err := s.Read(context.Background(), l.ID)
	if err != nil {
		t.Fatal(err)
	}
	r.Generation++
	if err = s.save(context.Background(), r, false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.complete(context.Background(), l, []Observation{observation(t, s, "candidate", "hello")}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale generation accepted: %v", err)
	}
}

func TestCompletionExpiry(t *testing.T) {
	s, _ := testStore(t)
	p := testPlan()
	l := begin(t, s, p)
	r, err := s.Read(context.Background(), l.ID)
	if err != nil {
		t.Fatal(err)
	}
	// A valid but already expired plan simulates passage of time without sleeps.
	r.Request.Plan.ExpiresAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	r.RequestDigest = objectDigest("qualification-request-v1", r.Request)
	r.PlanDigest = objectDigest("qualification-plan-v1", r.Request.Plan)
	if err = s.save(context.Background(), r, false); err != nil {
		t.Fatal(err)
	}
	done, err := s.complete(context.Background(), l, []Observation{observation(t, s, "candidate", "hello")})
	if err != nil || done.State != Incomplete {
		t.Fatalf("expired completion: %s %v", done.State, err)
	}
}
