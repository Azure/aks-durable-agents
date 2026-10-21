package qualification

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestWorkspaceDomain(t *testing.T) {
	s, dir := testStore(t)
	ctx := context.Background()
	accepted := []string{"workspace", "équipe", strings.Repeat("w", 129), strings.Repeat("w", 256), strings.Repeat("é", 128), strings.Repeat("🌿", 64), "workspace with spaces", "e\u0301quipe"}
	ids := map[string]string{}
	for _, workspace := range accepted {
		p := testPlan()
		p.Subject.Workspace = workspace
		r, err := s.Admit(ctx, Request{Key: "key", Requester: "caller", Plan: p})
		if err != nil {
			t.Fatalf("workspace %q: %v", workspace, err)
		}
		for previous, id := range ids {
			if id == r.ID {
				t.Fatalf("workspace %q reused namespace %q", workspace, previous)
			}
		}
		ids[workspace] = r.ID
		same, err := s.Admit(ctx, Request{Key: "key", Requester: "caller", Plan: p})
		if err != nil || same.ID != r.ID {
			t.Fatalf("same namespace retry: %v", err)
		}
	}
	for name, workspace := range map[string]string{"empty": "", "too long": strings.Repeat("w", 257), "unicode too long": strings.Repeat("é", 128) + "x", "invalid utf8": string([]byte{0xff}), "nul": "work\x00space", "tab": "work\tspace", "newline": "work\nspace", "del": "work\x7fspace", "unicode control": "work\u0085space"} {
		t.Run(name, func(t *testing.T) {
			p := testPlan()
			p.Subject.Workspace = workspace
			if _, err := s.Admit(ctx, Request{Key: "key", Requester: "caller", Plan: p}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid workspace accepted: %v", err)
			}
		})
	}
	lineage := s.Lineage()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, lineage)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for workspace, id := range ids {
		r, err := reopened.Read(ctx, id)
		if err != nil || r.Request.Plan.Subject.Workspace != workspace {
			t.Fatalf("workspace changed on reopen: %q %v", workspace, err)
		}
	}
}
