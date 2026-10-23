package targetversions

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
)

func (r AbandonRequest) fingerprint() string {
	return hash("g1-abandon-v1", append([]string{r.OperationID, number(r.ExpectedRevision), number(r.Generation), r.Key, r.Reason}, r.Authority.fields()...)...)
}
func (s *Store) StartAbandon(ctx context.Context, r AbandonRequest) (Operation, error) {
	if !keyOK(r.Key) || !reasonOK(r.Reason) || !bounded(r) {
		return Operation{}, ErrInvalid
	}
	fp := r.fingerprint()
	return s.change(ctx, r.Step, func(q query, t *Target, o *Operation) (bool, []Link, error) {
		var kind, id, saved string
		e := q.QueryRowContext(ctx, "SELECT kind,operation,fingerprint FROM request_keys WHERE target=? AND key=?", t.ID, r.Key).Scan(&kind, &id, &saved)
		if e == nil {
			if kind == "abandon" && id == o.ID && fp == saved && o.Abandonment != nil {
				return false, nil, nil
			}
			return false, nil, ErrConflict
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return false, nil, e
		}
		if o.Phase != "reserved" && o.Phase != "predecessor-retired" {
			return false, nil, ErrConflict
		}
		at := s.now()
		if !r.Authority.bound(*o) || !r.Authority.valid(t.ID, "abandon_activation", at) {
			return false, nil, ErrConflict
		}
		a := Abandonment{IntentID: rand.Text(), ID: rand.Text(), Key: r.Key, Reason: r.Reason, Fingerprint: fp, LastPhase: o.Phase, Authority: r.Authority, CreatedAt: at}
		// Intent, decision claim and tombstone share the same writer transaction as
		// the phase CAS. A cleanup capability cannot be used for old forward steps.
		var used string
		e = q.QueryRowContext(ctx, "SELECT operation FROM decision_claims WHERE store_id=? AND id=?", r.Authority.DecisionRecord.StoreID, r.Authority.DecisionRecord.ID).Scan(&used)
		if e == nil {
			return false, nil, ErrConflict
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return false, nil, e
		}
		if e = put(ctx, q, "INSERT INTO decision_claims VALUES(?,?,?,'abandon')", r.Authority.DecisionRecord.StoreID, r.Authority.DecisionRecord.ID, o.ID); e != nil {
			return false, nil, e
		}
		if e = put(ctx, q, "INSERT INTO request_keys VALUES(?,?,'abandon',?,?)", t.ID, r.Key, o.ID, fp); e != nil {
			return false, nil, e
		}
		if e = put(ctx, q, "INSERT INTO abandonments VALUES(?,?,?)", a.ID, o.ID, encoded(a)); e != nil {
			return false, nil, e
		}
		if e = put(ctx, q, "INSERT INTO tombstones VALUES(?,?)", o.ID, a.IntentID); e != nil {
			return false, nil, e
		}
		o.Abandonment = &a
		o.Phase = "abandoning"
		t.Availability = "unavailable"
		return true, pair("abandonment", o.ID, a.ID), nil
	})
}
func (s *Store) retirementProof(ctx context.Context, q query, o Operation, r Receipt, cleanup bool) error {
	prefix := ""
	intent := ""
	if cleanup {
		prefix = "abandon_"
		intent = o.Abandonment.IntentID
	}
	kind := "retired"
	if o.FrozenSource == nil {
		kind = "no_source"
	}
	if o.Request.Predecessor.Kind == "abandonment" && o.FrozenSource != nil {
		kind = "already_retired"
	}
	if !s.validReceipt(o, r, prefix+kind, intent) {
		return ErrConflict
	}
	if kind == "already_retired" {
		previous, e := terminal(ctx, q, o.Request.Predecessor.ID)
		if e != nil {
			return e
		}
		p := terminalReceipt(previous)
		if p == nil || r.PredecessorEvidence != p.EvidenceDigest {
			return ErrConflict
		}
	} else if r.PredecessorEvidence != "" {
		return ErrConflict
	}
	return nil
}
func terminalReceipt(o Operation) *Receipt {
	for _, kind := range []string{"abandon_retired", "abandon_already_retired", "abandon_no_source"} {
		if r := findReceipt(o, kind); r != nil {
			return r
		}
	}
	return nil
}
func (s *Store) FinishAbandon(ctx context.Context, st Step, predecessor, successor Receipt) (Operation, error) {
	return s.change(ctx, st, func(q query, t *Target, o *Operation) (bool, []Link, error) {
		if o.Abandonment == nil {
			return false, nil, ErrConflict
		}
		if e := s.retirementProof(ctx, q, *o, predecessor, true); e != nil {
			return false, nil, e
		}
		if !s.validReceipt(*o, successor, "successor_disabled", o.Abandonment.IntentID) {
			return false, nil, ErrConflict
		}
		if o.Phase == "abandoned-unavailable" {
			p := terminalReceipt(*o)
			n := findReceipt(*o, "successor_disabled")
			if p != nil && n != nil && same(*p, predecessor) && same(*n, successor) {
				return false, nil, nil
			}
			return false, nil, ErrConflict
		}
		if o.Phase != "abandoning" {
			return false, nil, ErrConflict
		}
		o.Receipts = append(o.Receipts, predecessor, successor)
		o.Phase = "abandoned-unavailable"
		t.ActiveVersionID = ""
		t.OperationID = ""
		t.Availability = "unavailable"
		t.Predecessor = PredecessorRef{"abandonment", o.Abandonment.ID}
		return true, nil, nil
	})
}
