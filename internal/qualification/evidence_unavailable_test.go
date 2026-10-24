package qualification

import (
	"context"
	"errors"
	"io"
	"syscall"
	"testing"
	"time"
)

func TestEvidenceReadIOUnavailable(t *testing.T) {
	for _, phase := range []string{"completion", "activation"} {
		t.Run(phase, func(t *testing.T) {
			s, _ := testStore(t)
			p := testPlan()
			l := begin(t, s, p)
			obs := []Observation{observation(t, s, "candidate", "hello")}
			if phase == "completion" {
				cancelCompletion(t, s, l, obs, "BEGIN IMMEDIATE")
			} else if _, err := s.complete(context.Background(), l, obs); err != nil {
				t.Fatal(err)
			}
			before, err := s.Read(context.Background(), l.ID)
			if err != nil {
				t.Fatal(err)
			}
			original := blobReadAll
			fault := true
			calls := 0
			blobReadAll = func(reader io.Reader) ([]byte, error) {
				if fault {
					calls++
					return nil, syscall.EIO
				}
				return original(reader)
			}
			t.Cleanup(func() { blobReadAll = original })
			if phase == "completion" {
				_, err = s.complete(context.Background(), l, obs)
			} else {
				_, err = s.VerifyForActivation(context.Background(), l.ID, p, time.Now())
			}
			if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrIntegrity) || calls != 1 {
				t.Fatalf("evidence IO misclassified or not exercised: calls=%d err=%v", calls, err)
			}
			after, err := s.Read(context.Background(), l.ID)
			if err != nil || after.Digest != before.Digest {
				t.Fatalf("IO failure changed retained verdict/intent: %v", err)
			}
			fault = false
			if phase == "completion" {
				done, err := s.complete(context.Background(), l, obs)
				if err != nil || done.State != Passed {
					t.Fatalf("IO retry did not resume: %s %v", done.State, err)
				}
			}
			if _, err = s.VerifyForActivation(context.Background(), l.ID, p, time.Now()); err != nil {
				t.Fatalf("retained evidence failed after IO restored: %v", err)
			}
		})
	}
}
