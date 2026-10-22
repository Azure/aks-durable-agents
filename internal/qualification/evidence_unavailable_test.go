package qualification

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEvidenceReadIOUnavailable(t *testing.T) {
	const key = "QUALIFICATION_EVIDENCE_IO_DIR"
	if dir := os.Getenv(key); dir != "" {
		s, err := Open(dir, os.Getenv("QUALIFICATION_EVIDENCE_IO_LINEAGE"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		r, err := s.Read(context.Background(), os.Getenv("QUALIFICATION_EVIDENCE_IO_ID"))
		if err != nil {
			t.Fatal(err)
		}
		if r.State == Passed {
			_, err = s.VerifyForActivation(context.Background(), r.ID, r.Request.Plan, time.Now())
		} else {
			_, err = s.complete(context.Background(), lease{r.ID, r.Generation}, r.Observations)
		}
		if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrIntegrity) {
			t.Fatalf("evidence IO misclassified: %v", err)
		}
		after, err := s.Read(context.Background(), r.ID)
		if err != nil || after.Digest != r.Digest {
			t.Fatalf("IO failure changed retained verdict/intent: %v", err)
		}
		return
	}
	strace, err := exec.LookPath("strace")
	if err != nil {
		t.Skip("read IO fault injection requires strace")
	}
	for _, phase := range []string{"completion", "activation"} {
		t.Run(phase, func(t *testing.T) {
			s, dir := testStore(t)
			p := testPlan()
			l := begin(t, s, p)
			obs := []Observation{observation(t, s, "candidate", "hello")}
			if phase == "completion" {
				cancelCompletion(t, s, l, obs, "BEGIN IMMEDIATE")
			} else {
				if _, err = s.complete(context.Background(), l, obs); err != nil {
					t.Fatal(err)
				}
			}
			lineage := s.Lineage()
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "evidence", obs[0].Candidate.Blob.Digest[7:])
			trace := filepath.Join(privateTestDir(t), "read.trace")
			cmd := exec.Command(strace, "-f", "-qq", "-yy", "-e", "trace=read", "-e", "inject=read:error=EIO", "-P", path, "-o", trace, os.Args[0], "-test.run=^TestEvidenceReadIOUnavailable$")
			cmd.Env = append(os.Environ(), key+"="+dir, "QUALIFICATION_EVIDENCE_IO_LINEAGE="+lineage, "QUALIFICATION_EVIDENCE_IO_ID="+l.ID)
			output, err := cmd.CombinedOutput()
			if err != nil {
				if strings.Contains(string(output), "ptrace") && strings.Contains(string(output), "Operation not permitted") {
					t.Skipf("read fault injection unavailable: %s", output)
				}
				t.Fatalf("evidence IO probe: %v\n%s", err, output)
			}
			calls, err := os.ReadFile(trace)
			if err != nil || !strings.Contains(string(calls), "read(") || !strings.Contains(string(calls), "EIO") {
				t.Fatalf("read fault not exercised: %s %v", calls, err)
			}
			s, err = Open(dir, lineage)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
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
