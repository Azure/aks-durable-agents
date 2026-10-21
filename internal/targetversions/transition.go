package targetversions

import "context"

func findReceipt(o Operation, kind string) *Receipt {
	for i := range o.Receipts {
		if o.Receipts[i].Kind == kind {
			return &o.Receipts[i]
		}
	}
	return nil
}
func (s *Store) validReceipt(o Operation, r Receipt, kind string, intent string) bool {
	return bounded(r) && r.Kind == kind && r.OperationID == o.ID && r.TargetID == o.Request.TargetID && r.Generation == o.Generation && r.BackendLineageID == s.BackendLineageID && r.ExecutionContextID == o.Version.ExecutionContextID && r.ArtifactDigest == o.Request.Candidate.binding() && r.Predecessor == o.Request.Predecessor && digestOK(r.EvidenceDigest) && digestOK(r.FenceDigest) && digestOK(r.ContextDigest) && r.QualificationDigest == o.Request.Candidate.Qualification.Digest && r.IntentID == intent
}
func (s *Store) change(ctx context.Context, st Step, fn func(query, *Target, *Operation) (bool, []Link, error)) (out Operation, err error) {
	err = s.transact(ctx, func(q query) error {
		o, e := operation(ctx, q, st.OperationID)
		if e != nil {
			return e
		}
		if st.Generation != o.Generation {
			return ErrConflict
		}
		t, e := target(ctx, q, o.Request.TargetID)
		if e != nil {
			return e
		}
		matches := st.ExpectedRevision == o.Revision && t.OperationID == o.ID && t.Generation == o.Generation
		from := o.Phase
		changed, links, e := fn(q, &t, &o)
		if e != nil {
			return e
		}
		if !changed {
			out = o
			return nil
		}
		if !matches {
			return ErrConflict
		}
		tomb := ""
		if o.Phase == "abandoning" && from != "abandoning" {
			tomb = o.Abandonment.IntentID
		}
		if e = s.save(ctx, q, t, o, from, links, tomb); e != nil {
			return e
		}
		o.Revision++
		out = o
		return nil
	})
	return
}
func (s *Store) receiptStep(ctx context.Context, st Step, r Receipt, kind, from, to string, finish func(query, *Target, *Operation) ([]Link, error)) (Operation, error) {
	return s.change(ctx, st, func(q query, t *Target, o *Operation) (bool, []Link, error) {
		if o.Abandonment != nil || !s.validReceipt(*o, r, kind, "") {
			return false, nil, ErrConflict
		}
		if saved := findReceipt(*o, kind); saved != nil {
			if !same(*saved, r) {
				return false, nil, ErrConflict
			}
			return false, nil, nil
		}
		if o.Phase != from {
			return false, nil, ErrConflict
		}
		o.Phase = to
		o.Receipts = append(o.Receipts, r)
		var links []Link
		var e error
		if finish != nil {
			links, e = finish(q, t, o)
		}
		return true, links, e
	})
}
func (s *Store) MarkPrepared(ctx context.Context, st Step, r Receipt) (Operation, error) {
	return s.receiptStep(ctx, st, r, "prepared", "preparing", "prepared", nil)
}
func (s *Store) Reserve(ctx context.Context, st Step, a AuthorizationSnapshot) (Operation, error) {
	return s.change(ctx, st, func(q query, t *Target, o *Operation) (bool, []Link, error) {
		if o.Abandonment != nil {
			return false, nil, ErrConflict
		}
		if o.Reserved != nil {
			if same(*o.Reserved, a) {
				return false, nil, nil
			}
			return false, nil, ErrConflict
		}
		at := s.now()
		if o.Phase != "prepared" || !a.bound(*o) || !a.valid(t.ID, action(o.Request.Intent), at) || !same(a.DecisionRecord, o.Request.DecisionRecord) {
			return false, nil, ErrConflict
		}
		o.Reserved = &a
		o.ReservedAt = at
		o.Phase = "reserved"
		return true, nil, nil
	})
}
func (s *Store) MarkRetired(ctx context.Context, st Step, r Receipt) (Operation, error) {
	if r.Kind != "retired" && r.Kind != "no_source" && r.Kind != "already_retired" {
		return Operation{}, ErrConflict
	}
	return s.receiptStep(ctx, st, r, r.Kind, "reserved", "predecessor-retired", func(q query, t *Target, o *Operation) ([]Link, error) {
		return nil, s.retirementProof(ctx, q, *o, r, false)
	})
}
func (s *Store) Commit(ctx context.Context, st Step, r Receipt) (Operation, error) {
	return s.receiptStep(ctx, st, r, "commit", "predecessor-retired", "committed", func(q query, t *Target, o *Operation) ([]Link, error) {
		p := findReceipt(*o, "prepared")
		if p == nil || o.Reserved == nil {
			return nil, ErrIntegrity
		}
		if r.FenceDigest != p.FenceDigest || r.ContextDigest != p.ContextDigest {
			return nil, ErrConflict
		}
		t.ActiveVersionID = o.Version.ID
		t.Predecessor = PredecessorRef{"version", o.Version.ID}
		t.OperationID = ""
		t.Availability = "ready"
		var links []Link
		if o.Request.Predecessor.Kind == "version" {
			links = pair("predecessor", o.Request.Predecessor.ID, o.Version.ID)
		}
		return links, nil
	})
}
func (s *Store) StartAbort(ctx context.Context, st Step, reason string) (Operation, error) {
	if !reasonOK(reason) {
		return Operation{}, ErrInvalid
	}
	return s.change(ctx, st, func(q query, t *Target, o *Operation) (bool, []Link, error) {
		if o.AbortReason != "" {
			if o.AbortReason == reason {
				return false, nil, nil
			}
			return false, nil, ErrConflict
		}
		if o.Phase != "preparing" && o.Phase != "prepared" {
			return false, nil, ErrConflict
		}
		o.Phase = "aborting"
		o.AbortReason = reason
		return true, nil, nil
	})
}
func (s *Store) FinishAbort(ctx context.Context, st Step, r Receipt, refused bool) (Operation, error) {
	to := "aborted"
	if refused {
		to = "refused"
	}
	return s.change(ctx, st, func(q query, t *Target, o *Operation) (bool, []Link, error) {
		if !s.validReceipt(*o, r, "release", "") {
			return false, nil, ErrConflict
		}
		if saved := findReceipt(*o, "release"); saved != nil {
			if same(*saved, r) && o.Phase == to {
				return false, nil, nil
			}
			return false, nil, ErrConflict
		}
		if o.Phase != "aborting" {
			return false, nil, ErrConflict
		}
		o.Phase = to
		o.Receipts = append(o.Receipts, r)
		t.OperationID = ""
		t.Availability = "unavailable"
		if t.ActiveVersionID != "" {
			t.Availability = "ready"
		}
		return true, nil, nil
	})
}
