package targetversions

import (
	"context"
	"encoding/json"
	"strings"
)

// History is a bounded, ascending read. A nonpositive or oversized page is 100.
func (s *Store) History(ctx context.Context, targetID string, after uint64, limit int) ([]Event, error) {
	if !keyOK(targetID) {
		return nil, ErrInvalid
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	if after >= uint64(1<<63-1) {
		return []Event{}, ctx.Err()
	}
	rows, e := s.db.QueryContext(ctx, "SELECT data FROM events WHERE target=? AND sequence>? ORDER BY sequence LIMIT ?", targetID, after, limit)
	if e != nil {
		return nil, normalizeError(ctx, e)
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var b []byte
		var ev Event
		if e = rows.Scan(&b); e != nil {
			return nil, normalizeError(ctx, e)
		}
		if e = json.Unmarshal(b, &ev); e != nil {
			return nil, normalizeError(ctx, e)
		}
		out = append(out, ev)
	}
	return out, normalizeError(ctx, rows.Err())
}

// Verify certifies local references/projections only, not runtime fences, artifact
// bytes, other stores, stopped writers or rollback-resistant restore continuity.
// A failed check latches this handle against further mutation; it never repairs.
func (s *Store) Verify(ctx context.Context) error {
	return s.transaction(ctx, true, func(q query) error { return s.verify(ctx, q) })
}

type factRows struct {
	selectSQL string
	rows      map[string][]byte
}

func (f *factRows) add(key string, value []byte) bool {
	if old, ok := f.rows[key]; ok {
		return string(old) == string(value)
	}
	f.rows[key] = value
	return true
}
func rowKey(v ...string) string { return strings.Join(v, "\x00") }
func (s *Store) verify(ctx context.Context, q query) error {
	if e := s.basicVerify(ctx, q); e != nil {
		return e
	}
	var version, count int
	var id, backend string
	if e := q.QueryRowContext(ctx, "SELECT schema_version,store_id,backend_id FROM metadata WHERE singleton=1").Scan(&version, &id, &backend); e != nil {
		return e
	}
	if version != 1 {
		return ErrUnsupported
	}
	if id != s.ID || backend != s.BackendLineageID || !keyOK(id) || !keyOK(backend) {
		return ErrIntegrity
	}
	if e := q.QueryRowContext(ctx, "SELECT count(*) FROM metadata").Scan(&count); e != nil || count != 1 {
		return ErrIntegrity
	}
	expectedSchema := map[string]string{}
	for _, stmt := range schema {
		expectedSchema[strings.Fields(stmt)[2]] = strings.Join(strings.Fields(stmt), " ")
	}
	rows, e := q.QueryContext(ctx, "SELECT name,sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if e != nil {
		return e
	}
	for rows.Next() {
		var name, stmt string
		if e = rows.Scan(&name, &stmt); e != nil {
			break
		}
		if expectedSchema[name] != strings.Join(strings.Fields(stmt), " ") {
			e = ErrIntegrity
			break
		}
		delete(expectedSchema, name)
	}
	readErr := rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if readErr != nil {
		return readErr
	}
	if len(expectedSchema) != 0 {
		return ErrIntegrity
	}
	facts := map[string]*factRows{}
	for name, selectSQL := range map[string]string{
		"targets": "SELECT id,data FROM targets", "operations": "SELECT id,data FROM operations", "operation_state": "SELECT id,data FROM operation_state", "versions": "SELECT id,data FROM versions",
		"qualifications": "SELECT store_id||char(0)||id,data FROM qualifications", "abandonments": "SELECT id,data FROM abandonments",
		"request_keys":    "SELECT target||char(0)||key,json_array(kind,operation,fingerprint) FROM request_keys",
		"decision_claims": "SELECT store_id||char(0)||id,json_array(operation,kind) FROM decision_claims",
		"links":           "SELECT kind||char(0)||from_id||char(0)||to_id,'1' FROM links", "tombstones": "SELECT operation,intent FROM tombstones",
	} {
		facts[name] = &factRows{selectSQL: selectSQL, rows: map[string][]byte{}}
	}
	events := []Event{}
	rows, e = q.QueryContext(ctx, "SELECT target,sequence,data FROM events ORDER BY target,sequence")
	if e != nil {
		return e
	}
	for rows.Next() {
		var b []byte
		var ev Event
		var targetID string
		var sequence uint64
		if e = rows.Scan(&targetID, &sequence, &b); e != nil {
			break
		}
		if e = json.Unmarshal(b, &ev); e != nil {
			break
		}
		if ev.TargetID != targetID || ev.Sequence != sequence {
			e = ErrIntegrity
			break
		}
		events = append(events, ev)
	}
	readErr = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if readErr != nil {
		return readErr
	}
	targets := map[string]Target{}
	ops := map[string]Operation{}
	for _, ev := range events {
		previous := targets[ev.TargetID]
		if ev.Sequence != previous.Revision+1 || ev.Target.ID != ev.TargetID || ev.Target.StoreID != s.ID || ev.BackendLineageID != s.BackendLineageID || ev.At.IsZero() {
			return ErrIntegrity
		}
		if previous.Revision == 0 {
			t := Target{ID: ev.TargetID, Kind: "ordinary", StoreID: s.ID, GenesisID: ev.Target.GenesisID, Predecessor: PredecessorRef{"genesis", ev.Target.GenesisID}, Revision: 1, Availability: "unavailable"}
			if !keyOK(t.ID) || !keyOK(t.GenesisID) || !same(t, ev.Target) || ev.Operation != nil || ev.OperationID != "" || ev.FromPhase != "" || ev.ToPhase != "" || len(ev.Links) != 0 || ev.Tombstone != "" {
				return ErrIntegrity
			}
			targets[t.ID] = t
			continue
		}
		if ev.Operation == nil {
			return ErrIntegrity
		}
		o := *ev.Operation
		old, exists := ops[o.ID]
		var want Operation
		var t Target
		var links []Link
		var tomb string
		if !exists {
			r := o.Request
			v := o.Version
			if !r.valid() || r.TargetID != previous.ID || r.Predecessor != previous.Predecessor || r.ExpectedRevision != previous.Revision || previous.OperationID != "" || !keyOK(o.ID) || !keyOK(v.ID) || !keyOK(v.ExecutionContextID) || v.TargetID != r.TargetID || v.OperationID != o.ID || v.CreatedAt.IsZero() || !same(v.Candidate, r.Candidate) {
				return ErrIntegrity
			}
			source, e := s.source(ctx, q, previous, r)
			if e != nil {
				return ErrIntegrity
			}
			want = Operation{ID: o.ID, Fingerprint: r.fingerprint(), Phase: "preparing", Revision: 1, Generation: previous.Generation + 1, Request: r, Version: v, FrozenSource: source}
			t = previous
			t.Generation = want.Generation
			t.OperationID = o.ID
			t.Availability = "fenced"
			if r.Predecessor.Kind == "abandonment" {
				links = append(links, pair("attempt", r.Predecessor.ID, o.ID)...)
			}
			if r.SourceVersionID != "" {
				links = append(links, pair("source", r.SourceVersionID, v.ID)...)
			}
			if ev.FromPhase != "" || !facts["operations"].add(o.ID, encoded(want)) || !facts["versions"].add(v.ID, encoded(v)) || !facts["request_keys"].add(rowKey(r.TargetID, r.Key), encoded([]string{"begin", o.ID, r.fingerprint()})) || !facts["decision_claims"].add(rowKey(r.DecisionRecord.StoreID, r.DecisionRecord.ID), encoded([]string{o.ID, "begin"})) || !facts["qualifications"].add(rowKey(r.Candidate.Qualification.StoreID, r.Candidate.Qualification.ID), encoded(r.Candidate.Qualification)) {
				return ErrIntegrity
			}
		} else {
			if previous.OperationID != o.ID || previous.Generation != o.Generation || ev.FromPhase != old.Phase {
				return ErrIntegrity
			}
			var e error
			want, t, links, tomb, e = s.replayStep(ctx, q, previous, old, o)
			if e != nil {
				return ErrIntegrity
			}
		}
		t.Revision++
		if !same(want, o) || !same(t, ev.Target) || ev.OperationID != o.ID || ev.ToPhase != o.Phase || !sameLinks(links, ev.Links) || ev.Tombstone != tomb {
			return ErrIntegrity
		}
		targets[t.ID] = t
		ops[o.ID] = o
		for _, l := range links {
			if !facts["links"].add(rowKey(l.Kind, l.FromID, l.ToID), []byte("1")) {
				return ErrIntegrity
			}
		}
		if o.Phase == "abandoning" && old.Abandonment == nil {
			a := o.Abandonment
			if !facts["abandonments"].add(a.ID, encoded(*a)) || !facts["request_keys"].add(rowKey(t.ID, a.Key), encoded([]string{"abandon", o.ID, a.Fingerprint})) || !facts["decision_claims"].add(rowKey(a.Authority.DecisionRecord.StoreID, a.Authority.DecisionRecord.ID), encoded([]string{o.ID, "abandon"})) || !facts["tombstones"].add(o.ID, []byte(a.IntentID)) {
				return ErrIntegrity
			}
		}
	}
	for id, t := range targets {
		facts["targets"].add(id, encoded(t))
	}
	for id, o := range ops {
		facts["operation_state"].add(id, encoded(o))
	}
	for _, f := range facts {
		rows, e = q.QueryContext(ctx, f.selectSQL)
		if e != nil {
			return e
		}
		seen := 0
		for rows.Next() {
			var key string
			var value []byte
			if e = rows.Scan(&key, &value); e != nil {
				break
			}
			expected, ok := f.rows[key]
			if !ok || string(expected) != string(value) {
				e = ErrIntegrity
				break
			}
			seen++
		}
		readErr = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if readErr != nil {
			return readErr
		}
		if seen != len(f.rows) {
			return ErrIntegrity
		}
	}
	// Scalar FK columns must agree with their immutable snapshots as well.
	for _, stmt := range []string{`SELECT count(*) FROM operations WHERE id!=json_extract(data,'$.ID') OR target!=json_extract(data,'$.Request.TargetID') OR decision_store!=json_extract(data,'$.Request.DecisionRecord.StoreID') OR decision_id!=json_extract(data,'$.Request.DecisionRecord.ID')`, `SELECT count(*) FROM versions WHERE id!=json_extract(data,'$.ID') OR target!=json_extract(data,'$.TargetID') OR operation!=json_extract(data,'$.OperationID')`, `SELECT count(*) FROM abandonments WHERE operation!=(SELECT id FROM operation_state WHERE json_extract(operation_state.data,'$.Abandonment.ID')=abandonments.id)`} {
		if e = q.QueryRowContext(ctx, stmt).Scan(&count); e != nil || count != 0 {
			return ErrIntegrity
		}
	}
	return nil
}
func sameLinks(a, b []Link) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return same(a, b)
}
func sameReceipts(a, b []Receipt) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return same(a, b)
}
func (s *Store) replayStep(ctx context.Context, q query, t Target, old, o Operation) (Operation, Target, []Link, string, error) {
	want := old
	want.Revision++
	want.Phase = o.Phase
	var links []Link
	var tomb string
	bad := func() (Operation, Target, []Link, string, error) { return want, t, nil, "", ErrIntegrity }
	receipt := func(kind string) *Receipt {
		if len(o.Receipts) != len(old.Receipts)+1 || !sameReceipts(o.Receipts[:len(old.Receipts)], old.Receipts) {
			return nil
		}
		r := o.Receipts[len(old.Receipts)]
		if !s.validReceipt(old, r, kind, "") {
			return nil
		}
		want.Receipts = o.Receipts
		return &r
	}
	switch o.Phase {
	case "prepared":
		if old.Phase != "preparing" || receipt("prepared") == nil {
			return bad()
		}
	case "reserved":
		if old.Phase != "prepared" || o.Reserved == nil || !o.Reserved.bound(old) || !o.Reserved.valid(t.ID, action(old.Request.Intent), o.ReservedAt) || !same(o.Reserved.DecisionRecord, old.Request.DecisionRecord) {
			return bad()
		}
		want.Reserved = o.Reserved
		want.ReservedAt = o.ReservedAt
	case "predecessor-retired":
		if old.Phase != "reserved" || len(o.Receipts) == 0 {
			return bad()
		}
		r := o.Receipts[len(o.Receipts)-1]
		if receipt(r.Kind) == nil || s.retirementProof(ctx, q, old, r, false) != nil {
			return bad()
		}
	case "committed":
		r := receipt("commit")
		p := findReceipt(old, "prepared")
		if old.Phase != "predecessor-retired" || r == nil || p == nil || r.ContextDigest != p.ContextDigest || r.FenceDigest != p.FenceDigest {
			return bad()
		}
		t.ActiveVersionID = o.Version.ID
		t.OperationID = ""
		t.Availability = "ready"
		t.Predecessor = PredecessorRef{"version", o.Version.ID}
		if old.Request.Predecessor.Kind == "version" {
			links = pair("predecessor", old.Request.Predecessor.ID, o.Version.ID)
		}
	case "aborting":
		if (old.Phase != "preparing" && old.Phase != "prepared") || !reasonOK(o.AbortReason) {
			return bad()
		}
		want.AbortReason = o.AbortReason
	case "aborted", "refused":
		if old.Phase != "aborting" || receipt("release") == nil {
			return bad()
		}
		t.OperationID = ""
		t.Availability = "unavailable"
		if t.ActiveVersionID != "" {
			t.Availability = "ready"
		}
	case "abandoning":
		a := o.Abandonment
		if (old.Phase != "reserved" && old.Phase != "predecessor-retired") || a == nil || a.LastPhase != old.Phase || !keyOK(a.ID) || !keyOK(a.IntentID) || !keyOK(a.Key) || !reasonOK(a.Reason) || !a.Authority.bound(old) || !a.Authority.valid(t.ID, "abandon_activation", a.CreatedAt) {
			return bad()
		}
		r := AbandonRequest{Step: Step{old.ID, old.Revision, old.Generation}, Key: a.Key, Reason: a.Reason, Authority: a.Authority}
		if r.fingerprint() != a.Fingerprint {
			return bad()
		}
		want.Abandonment = a
		t.Availability = "unavailable"
		links = pair("abandonment", o.ID, a.ID)
		tomb = a.IntentID
	case "abandoned-unavailable":
		if old.Phase != "abandoning" || len(o.Receipts) != len(old.Receipts)+2 || !sameReceipts(o.Receipts[:len(old.Receipts)], old.Receipts) {
			return bad()
		}
		p, n := o.Receipts[len(old.Receipts)], o.Receipts[len(old.Receipts)+1]
		if s.retirementProof(ctx, q, old, p, true) != nil || !s.validReceipt(old, n, "successor_disabled", old.Abandonment.IntentID) {
			return bad()
		}
		want.Receipts = o.Receipts
		t.OperationID = ""
		t.ActiveVersionID = ""
		t.Availability = "unavailable"
		t.Predecessor = PredecessorRef{"abandonment", old.Abandonment.ID}
	default:
		return bad()
	}
	return want, t, links, tomb, nil
}
