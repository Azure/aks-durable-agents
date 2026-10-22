package host

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"github.com/agent-primitives/sessions/client"
	"github.com/agent-primitives/sessions/sqlitelog"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	otherSessionOID  = "0c0c0c0c-0000-4000-8000-000000000003"
	listedSessionOID = "0b0b0b0b-0000-4000-8000-000000000002"
	roleSessionOID   = "0d0d0d0d-0000-4000-8000-000000000004"
)

func requiredSessionFixture(t *testing.T) (*hostFixture, func(string) context.Context) {
	t.Helper()
	f := newHostFixture(t)
	identity, sign := entraFixture(t, func(claims jwt.MapClaims) {
		claims["roles"] = []string{"Reader"}
		// Ownership is sufficient for ordinary reads/actions, even without roles.
		if claims["oid"] == ownerOID {
			delete(claims, "roles")
		}
		if claims["oid"] == roleSessionOID {
			claims["roles"] = []string{"Approver"}
		}
	})
	identity.ApproverRoles = []string{"Approver"}
	f.config.Mode, f.config.Identity = authn.Required, identity
	f.config.Approvers = []api.CallerIdentity{{Issuer: fixtureIssuer, Subject: listedSessionOID}}
	return f, func(subject string) context.Context { return bearer(t.Context(), "Bearer "+sign(subject)) }
}

// Catches missing assembled-service authorization on unary metadata and streamed
// journal records for an unrelated, otherwise admitted caller.
func TestSessionAuthorizationCrossUserRead(t *testing.T) {
	f, caller := requiredSessionFixture(t)
	_, c, _ := f.start(t)
	turn, err := c.Exec(caller(ownerOID), client.ExecOptions{Harness: "release-notes", Inputs: []string{"private proposal"}})
	if err != nil {
		t.Fatal(err)
	}
	uid := turn.Session.GetMetadata().GetUid()
	if s, err := c.GetSession(caller(otherSessionOID), uid); status.Code(err) != codes.PermissionDenied || s != nil {
		t.Errorf("foreign GetSession: payload=%v code=%v want PermissionDenied", s != nil, status.Code(err))
	}
	stream, err := c.Sessions().Replay(caller(otherSessionOID), &v1.ReplayRequest{Session: uid})
	if err != nil {
		t.Fatal(err)
	}
	record, err := stream.Recv()
	if status.Code(err) != codes.PermissionDenied || record != nil {
		t.Errorf("foreign Replay: payload=%v code=%v want PermissionDenied", record != nil, status.Code(err))
	}
}

// Creation captures verified identity, never supplied provenance. Filtering must
// happen before pagination, survive restart, and apply to approvers too.
func TestSessionAuthorizationOwnerCaptureAndListing(t *testing.T) {
	f, caller := requiredSessionFixture(t)
	app, c, stop := f.start(t)
	want := map[string][]string{}
	for _, subject := range []string{ownerOID, otherSessionOID, listedSessionOID, roleSessionOID, ownerOID} {
		s, err := c.CreateSession(caller(subject), &v1.Session{Harness: "release-notes", Identity: &v1.IdentityRef{Issuer: fixtureIssuer, Subject: otherSessionOID}})
		if err != nil {
			t.Fatal(err)
		}
		uid := s.GetMetadata().GetUid()
		want[subject] = append(want[subject], uid)
		info, err := app.store.SessionInfo(uid)
		if err != nil || info.Owner != (api.CallerIdentity{Issuer: fixtureIssuer, Subject: subject}) {
			t.Errorf("CreateSession owner=%+v error=%v", info.Owner, err)
		}
	}
	turn, err := c.Exec(caller(ownerOID), client.ExecOptions{Harness: "release-notes", Inputs: []string{"implicit private session"}})
	if err != nil {
		t.Fatal(err)
	}
	uid := turn.Session.GetMetadata().GetUid()
	want[ownerOID] = append(want[ownerOID], uid)
	info, err := app.store.SessionInfo(uid)
	if err != nil || info.Owner != (api.CallerIdentity{Issuer: fixtureIssuer, Subject: ownerOID}) {
		t.Errorf("implicit Exec owner=%+v error=%v", info.Owner, err)
	}
	if err := app.store.PutSession(sqlitelog.SessionMeta{UID: "legacy-unbound", Harness: "release-notes"}); err != nil {
		t.Fatal(err)
	}
	stop()
	_, c, _ = f.start(t)
	for subject, uids := range want {
		t.Run(subject, func(t *testing.T) {
			var got []string
			token := ""
			for range len(uids) + 2 {
				page, err := c.ListSessionsPage(caller(subject), "", 1, token)
				if err != nil {
					t.Fatal(err)
				}
				for _, s := range page.GetSessions() {
					got = append(got, s.GetMetadata().GetUid())
				}
				token = page.GetNextPageToken()
				if token == "" {
					break
				}
			}
			slices.Sort(got)
			slices.Sort(uids)
			if token != "" || !slices.Equal(got, uids) {
				t.Errorf("owner-only pages: got=%v want=%v unfinished=%v", got, uids, token != "")
			}
			for _, uid := range uids {
				if s, err := c.GetSession(caller(subject), uid); err != nil || s == nil {
					t.Errorf("owner read after restart: %v", err)
				}
			}
		})
	}
	if f.models.Load() != 1 || f.sockets.Load() != 0 {
		t.Fatal("create/list/read invoked extra model or publication")
	}
}

// All 11 RPCs cross the assembled authentication/authorization boundary. Invalid
// tuples/routes and absent IDs cannot reveal validation or resource existence.
func TestSessionAuthorizationDeniedRPCs(t *testing.T) {
	f, caller := requiredSessionFixture(t)
	app, c, _ := f.start(t)
	turn, err := c.Exec(caller(ownerOID), client.ExecOptions{Harness: "release-notes", Inputs: []string{"private proposal"}})
	if err != nil {
		t.Fatal(err)
	}
	uid := turn.Session.GetMetadata().GetUid()
	if err := app.store.PutSession(sqlitelog.SessionMeta{UID: "legacy-unbound", Harness: "release-notes"}); err != nil {
		t.Fatal(err)
	}
	operations := []struct {
		name, privilege string
		call            func(context.Context, string) (bool, error)
	}{
		{"CreateSession", "global", func(ctx context.Context, _ string) (bool, error) {
			s, e := c.CreateSession(ctx, &v1.Session{})
			return s != nil, e
		}},
		{"ListSessions", "global", func(ctx context.Context, _ string) (bool, error) {
			s, e := c.ListSessionsPage(ctx, "", 1, "invalid-cursor")
			return s != nil, e
		}},
		{"GetSession", "approver", func(ctx context.Context, id string) (bool, error) { s, e := c.GetSession(ctx, id); return s != nil, e }},
		{"Replay", "approver", func(ctx context.Context, id string) (bool, error) {
			s, e := c.Sessions().Replay(ctx, &v1.ReplayRequest{Session: id})
			if e != nil {
				return false, e
			}
			r, e := s.Recv()
			return r != nil, e
		}},
		{"Exec", "", func(ctx context.Context, id string) (bool, error) {
			r, e := c.Exec(ctx, client.ExecOptions{Session: id, Harness: "invalid-route", Inputs: []string{"must not run"}})
			return r != nil && (r.Session != nil || len(r.Records) != 0 || r.Output != ""), e
		}},
		{"Exec recovery", "", func(ctx context.Context, id string) (bool, error) {
			r, e := c.Exec(ctx, client.ExecOptions{Session: id})
			return r != nil && (r.Session != nil || len(r.Records) != 0 || r.Output != ""), e
		}},
		{"Approve", "approver", func(ctx context.Context, id string) (bool, error) {
			s, e := c.Approve(ctx, id, api.ApprovalDecision{})
			return s != nil, e
		}},
		{"Resume", "", func(ctx context.Context, id string) (bool, error) {
			s, e := c.Resume(ctx, id, false)
			return s != nil, e
		}},
		{"Suspend", "", func(ctx context.Context, id string) (bool, error) { s, e := c.Suspend(ctx, id); return s != nil, e }},
		{"Fork", "", func(ctx context.Context, id string) (bool, error) {
			s, e := c.Fork(ctx, id, client.ForkOptions{Count: 129})
			return len(s) != 0, e
		}},
		{"Cancel", "", func(ctx context.Context, id string) (bool, error) {
			s, e := c.Sessions().Cancel(ctx, &v1.CancelRequest{Session: id})
			return s != nil, e
		}},
		{"DeleteSession", "", func(ctx context.Context, id string) (bool, error) {
			s, e := c.DeleteSession(ctx, id)
			return s != nil, e
		}},
	}
	for _, principal := range []struct{ name, subject string }{
		{"owner", ownerOID}, {"other", otherSessionOID}, {"listed approver", listedSessionOID}, {"role approver", roleSessionOID}, {"unauthenticated", ""},
	} {
		subject := principal.subject
		for _, target := range []struct{ name, uid string }{
			{"owned", uid}, {"ownerless", "legacy-unbound"}, {"missing", "missing-session"}, {"empty", ""},
		} {
			id := target.uid
			for _, op := range operations {
				unauthenticated := subject == ""
				if op.privilege == "global" && (!unauthenticated || id != uid) {
					continue
				}
				if id == uid && subject == ownerOID && op.name != "Approve" {
					continue
				}
				if id == uid && (subject == listedSessionOID || subject == roleSessionOID) && op.privilege == "approver" {
					continue
				}
				if id == "" && !unauthenticated && (op.name == "Exec" || op.name == "Exec recovery") {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/%s", principal.name, target.name, op.name), func(t *testing.T) {
					before, err := app.store.ListSessions(sqlitelog.ListOptions{})
					if err != nil {
						t.Fatal(err)
					}
					var journalBefore any
					if id == uid || id == "legacy-unbound" {
						journalBefore, err = app.store.Session(id).Read(1)
						if err != nil {
							t.Fatal(err)
						}
					}
					runs, models, sockets := f.harness.runs.Load(), f.models.Load(), f.sockets.Load()
					ctx := t.Context()
					want := codes.Unauthenticated
					if !unauthenticated {
						ctx, want = caller(subject), codes.PermissionDenied
					}
					ctx, cancel := context.WithCancel(ctx)
					defer cancel()
					payload, err := op.call(ctx, id)
					if status.Code(err) != want || payload {
						t.Errorf("payload=%v error=%v want=%v", payload, err, want)
					}
					after, err := app.store.ListSessions(sqlitelog.ListOptions{})
					if err != nil || !reflect.DeepEqual(before, after) {
						t.Error("denial changed session rows/cursors")
					}
					if journalBefore != nil {
						journalAfter, err := app.store.Session(id).Read(1)
						if err != nil || !reflect.DeepEqual(journalBefore, journalAfter) {
							t.Error("denial changed journal")
						}
					}
					if f.harness.runs.Load() != runs || f.models.Load() != models || f.sockets.Load() != sockets {
						t.Error("denial invoked harness/model/tool")
					}
				})
			}
		}
	}
}

// Both configured approval sources disclose the full session and journal, but
// never confer execution. Owners alone cannot approve their own pending work.
func TestSessionAuthorizationApprovalAndOwnerLifecycle(t *testing.T) {
	for _, subject := range []string{listedSessionOID, roleSessionOID} {
		for _, approved := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%v", subject, approved), func(t *testing.T) {
				f, caller := requiredSessionFixture(t)
				app, c, _ := f.start(t)
				owner, approver := caller(ownerOID), caller(subject)
				turn, err := c.Exec(owner, client.ExecOptions{Harness: "release-notes", Inputs: []string{"private approval proposal"}})
				if err != nil {
					t.Fatal(err)
				}
				uid := turn.Session.GetMetadata().GetUid()
				read, err := c.GetSession(approver, uid)
				if err != nil || !proto.Equal(read, turn.Session) {
					t.Fatalf("approver full session read: %v", err)
				}
				ownerRecords, err := c.Replay(owner, uid, 0, 0)
				if err != nil || len(ownerRecords) == 0 {
					t.Fatalf("owner journal: %v", err)
				}
				records, err := c.Replay(approver, uid, 0, 0)
				if err != nil || !slices.EqualFunc(records, ownerRecords, func(a, b *v1.LogRecord) bool { return proto.Equal(a, b) }) {
					t.Fatalf("approver full journal read: %v", err)
				}
				d := decision(t, read, approved)
				if s, err := c.Approve(owner, uid, d); status.Code(err) != codes.PermissionDenied || s != nil {
					t.Fatalf("owner approval: %v", err)
				}
				before, err := app.store.Session(uid).Read(1)
				if err != nil {
					t.Fatal(err)
				}
				rowsBefore, err := app.store.ListSessions(sqlitelog.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := c.Sessions().Cancel(owner, &v1.CancelRequest{Session: uid}); status.Code(err) != codes.Unimplemented {
					t.Fatalf("owner Cancel: %v", err)
				}
				if children, err := c.Fork(owner, uid, client.ForkOptions{}); status.Code(err) != codes.FailedPrecondition || len(children) != 0 {
					t.Fatalf("required Fork: %v", err)
				}
				after, err := app.store.Session(uid).Read(1)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("refused Fork/Cancel changed journal")
				}
				rowsAfter, err := app.store.ListSessions(sqlitelog.ListOptions{})
				if err != nil || !reflect.DeepEqual(rowsBefore, rowsAfter) {
					t.Fatal("refused Fork/Cancel changed session rows")
				}
				response, err := c.Approve(approver, uid, d)
				if err != nil || response.GetDecision() == nil {
					t.Fatalf("approver decision: %v", err)
				}
				if f.models.Load() != 1 || f.sockets.Load() != 0 || f.harness.runs.Load() != 1 {
					t.Fatal("read/approval invoked computation or publication")
				}
				before, err = app.store.Session(uid).Read(1)
				if err != nil {
					t.Fatal(err)
				}
				// Approval must not permit recovery through either RPC.
				if _, err := c.Resume(approver, uid, false); status.Code(err) != codes.PermissionDenied {
					t.Fatalf("approver Resume: %v", err)
				}
				if r, err := c.Exec(approver, client.ExecOptions{Session: uid}); status.Code(err) != codes.PermissionDenied || r != nil && r.Session != nil {
					t.Fatalf("approver inputless Exec: %v", err)
				}
				after, err = app.store.Session(uid).Read(1)
				if err != nil || !reflect.DeepEqual(before, after) || f.harness.runs.Load() != 1 || f.models.Load() != 1 || f.sockets.Load() != 0 {
					t.Fatal("denied approver recovery changed journal or invoked computation/publication")
				}
				if _, err := c.Exec(owner, client.ExecOptions{Session: uid}); err != nil {
					t.Fatal(err)
				}
				wantEffects := int32(0)
				if approved {
					wantEffects = 1
				}
				if f.models.Load() != 1 || f.sockets.Load() != wantEffects {
					t.Fatal("owner recovery repeated model or wrong publication")
				}
				suspended, err := c.Suspend(owner, uid)
				if err != nil || suspended.GetComputeState() != v1.ComputeState_COMPUTE_COLD {
					t.Fatalf("owner Suspend: %v", err)
				}
				if _, err := c.Resume(owner, uid, false); err != nil {
					t.Fatalf("owner Resume: %v", err)
				}
				deleted, err := c.DeleteSession(owner, uid)
				if err != nil || deleted.GetDeletionState() != v1.DeletionState_DELETION_PENDING {
					t.Fatalf("owner DeleteSession: %v", err)
				}
			})
		}
	}
}

func TestSessionAuthorizationOffModeCompatibility(t *testing.T) {
	f := newHostFixture(t)
	app, c, _ := f.start(t)
	ctx := t.Context()
	created, err := c.CreateSession(ctx, &v1.Session{Harness: "release-notes"})
	if err != nil {
		t.Fatal(err)
	}
	uid := created.GetMetadata().GetUid()
	info, err := app.store.SessionInfo(uid)
	if err != nil || info.Owner != (api.CallerIdentity{}) {
		t.Fatalf("off-mode owner: %+v %v", info.Owner, err)
	}
	turn, err := c.Exec(ctx, client.ExecOptions{Session: uid, Inputs: []string{"unrestricted fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetSession(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if page, err := c.ListSessionsPage(ctx, "", 1, ""); err != nil || len(page.GetSessions()) != 1 {
		t.Fatalf("off list: %v", err)
	}
	if _, err := c.Approve(ctx, uid, decision(t, turn.Session, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Resume(ctx, uid, false); err != nil {
		t.Fatal(err)
	}
	if records, err := c.Replay(ctx, uid, 0, 0); err != nil || len(records) == 0 {
		t.Fatalf("off replay: %v", err)
	}
	children, err := c.Fork(ctx, uid, client.ForkOptions{})
	if err != nil || len(children) != 1 {
		t.Fatalf("off Fork: %v", err)
	}
	if f.models.Load() != 1 || f.sockets.Load() != 1 {
		t.Fatal("off-mode execution changed")
	}
}
