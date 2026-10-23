//go:build squadproof

package squadproof

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"

	"github.com/agent-primitives/sessions/eventlog"
	"github.com/agent-primitives/sessions/sqlitelog"
)

// DataSnapshot copies only recognized proof files. Writers must already be
// stopped: this is not an online SQLite backup or a hot-restart mechanism.
// No SQLite handle is ever opened on a source file, even to checkpoint it.
type DataSnapshot struct{ Dir string }

func NewDataSnapshot(data string, writersStopped bool) (*DataSnapshot, error) {
	if !writersStopped || !privateDirectory(data) {
		return nil, ErrInvalid
	}
	dir, err := os.MkdirTemp(filepath.Dir(data), ".proof-snapshot-")
	if err != nil {
		return nil, err
	}
	s := &DataSnapshot{Dir: dir}
	for _, base := range []string{"proof.db", "journal.db"} {
		for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
			err = copyPrivateFile(filepath.Join(data, base+suffix), filepath.Join(dir, base+suffix))
			if suffix != "" && errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				s.Close()
				return nil, err
			}
		}
	}
	return s, nil
}
func (s *DataSnapshot) Close() error { return os.RemoveAll(s.Dir) }

func snapshotProof(ctx context.Context, data string, replay bool) (Proof, error) {
	s, err := NewDataSnapshot(data, true)
	if err != nil {
		return Proof{}, err
	}
	defer s.Close()
	l, err := existingLedger(s.Dir)
	if err != nil {
		return Proof{}, err
	}
	defer l.Close()
	p, err := ledgerProof(ctx, l)
	if err != nil {
		return p, err
	}
	uri := url.URL{Scheme: "file", Path: filepath.Join(s.Dir, "journal.db")}
	store, err := sqlitelog.Open(uri.String())
	if err != nil {
		return p, err
	}
	defer store.Close()
	for _, op := range p.Operations {
		if op.SessionUID == "" || op.State == "uncertain" {
			if replay {
				return p, ErrHeld
			}
			continue
		}
		records, e := store.Session(op.SessionUID).Read(1)
		if e != nil {
			return p, e
		}
		if e = eventlog.NewFrom(records).Verify(); e != nil {
			return p, e
		}
		r := ReplayProof{SessionUID: op.SessionUID}
		if len(records) > 0 {
			last := records[len(records)-1]
			r.HeadSeq, r.HeadHash = last.Seq, last.Hash
		}
		if replay {
			if op.State != "terminal" {
				return p, ErrHeld
			}
			r, e = replayRecords(ctx, op.SessionUID, records, NewHarness(op.Member, proofDigest()))
			if e != nil {
				return p, e
			}
		}
		p.Replays = append(p.Replays, r)
	}
	p.Outcome = "inspected"
	if replay {
		if len(p.Operations) == 0 {
			return p, ErrHeld
		}
		for _, in := range p.Inputs {
			if in.State != "delivered" || in.ExecutionID == "" {
				return p, ErrHeld
			}
		}
		p.Outcome = "replayed"
	}
	return p, nil
}
