package sessionfixture

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/agent-primitives/sessions/eventlog"
)

var errBridgeNeedsCheckpoint = errors.New("demo strict replay requires a stopped/checkpointed snapshot")

// SQLite mode=ro can create empty WAL/SHM files on a cold WAL-mode database.
// Immutable reads avoid that, but ignore nonempty WAL. Never use them until the
// writer has stopped/checkpointed; preserve uncheckpointed data and refuse proof.
func bridgeNeedsWal(path string) (bool, error) {
	needed := false
	for _, suffix := range []string{"-wal", "-journal"} {
		f, err := os.OpenFile(path+suffix, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		info, err := f.Stat()
		closeErr := f.Close()
		if err != nil {
			return false, err
		}
		if closeErr != nil {
			return false, closeErr
		}
		if !info.Mode().IsRegular() {
			return false, errors.New("demo database sidecar must be regular")
		}
		needed = needed || info.Size() != 0
	}
	return needed, nil
}
func requireBridgeCheckpoint(path string) error {
	needed, err := bridgeNeedsWal(path)
	if err != nil {
		return err
	}
	if needed {
		return fmt.Errorf("%w; preserve nonempty WAL and reconcile on writable recovery scratch, never discard it", errBridgeNeedsCheckpoint)
	}
	return nil
}
func bridgeReadOnlyDB(path string, cold bool) (*sql.DB, error) {
	needed, err := bridgeNeedsWal(path)
	if err != nil {
		return nil, err
	}
	if needed {
		if cold {
			return nil, errBridgeNeedsCheckpoint
		}
		return readOnlyDB(path)
	}
	return readOnlyDBQuery(path, "mode=ro&immutable=1")
}
func readBridgeRecords(ctx context.Context, path, uid string) ([]eventlog.Record, error) {
	db, err := bridgeReadOnlyDB(path, true)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return readJournalRecordsDB(ctx, db, uid)
}
