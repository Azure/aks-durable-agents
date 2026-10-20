package democli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	_ "modernc.org/sqlite"
)

// seal is a demo-only final preparation write, not replay or a production repair
// operation. The runner must first stop and remove every writer pod.
func seal(ctx context.Context, data string, fixture fixtureFunc) (any, error) {
	if err := ownedPrivateDir(data); err != nil {
		return nil, err
	}
	st, err := readState(data, "completed.json")
	if err != nil {
		return nil, err
	}
	if st.Artifact == "" || st.ApprovalSeq <= st.Pending.RequestSeq {
		return nil, errors.New("sealing requires the completed demo snapshot")
	}
	if err := absent(data, "sealed.json"); err != nil {
		return nil, err
	}
	// Validate both files before SQLite can open either; mode=rw below never
	// creates a missing database or resets an empty/truncated store.
	for _, name := range []string{"journal.db", "publications.db"} {
		if err := ownedStore(filepath.Join(data, name)); err != nil {
			return nil, err
		}
	}
	if err := matchHead(ctx, filepath.Join(data, "journal.db"), st); err != nil {
		return nil, err
	}
	var before, after evidence
	if err := fixtureJSON(ctx, fixture, &before, "evidence", "--scenario", "v2", "--data", data); err != nil {
		return nil, err
	}
	httpBefore, err := meter(data)
	if err != nil {
		return nil, err
	}
	if before.RealModelCalls == nil || *before.RealModelCalls != 1 || before.FakeModelCalls != 0 || before.PublicationCount != 1 || before.ReceiptCount != 1 || len(before.Artifacts) != 1 || before.Artifacts[0].Name != st.Artifact || httpBefore != 1 {
		return nil, errors.New("sealing requires exactly the completed demo's model/effect inventory")
	}
	for _, name := range []string{"journal.db", "publications.db"} {
		if err := normalizeStore(ctx, filepath.Join(data, name)); err != nil {
			return nil, fmt.Errorf("seal %s: %w", name, err)
		}
	}
	if err := matchHead(ctx, filepath.Join(data, "journal.db"), st); err != nil {
		return nil, err
	}
	if err := fixtureJSON(ctx, fixture, &after, "evidence", "--scenario", "v2", "--data", data); err != nil {
		return nil, err
	}
	httpAfter, err := meter(data)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(before, after) || httpBefore != httpAfter {
		return nil, errors.New("sealing changed the logical model/effect inventory")
	}
	for _, name := range []string{"journal.db", "publications.db"} {
		for _, suffix := range []string{"-wal", "-shm"} {
			if _, err := os.Lstat(filepath.Join(data, name+suffix)); !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("sidecar remains after sealing: %s%s", name, suffix)
			}
		}
	}
	if err := writeState(data, "sealed.json", st); err != nil {
		return nil, err
	}
	return map[string]any{"session": st.Session, "sealed": true}, nil
}

func ownedStore(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || int(stat.Uid) != os.Getuid() || info.Size() < 100 || info.Size() > 64<<20 {
		return fmt.Errorf("%s is not a bounded existing owned demo store", filepath.Base(path))
	}
	return nil
}

func storeURL(path, mode string) string {
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=" + mode}
	return u.String()
}

func matchHead(ctx context.Context, path string, st state) error {
	db, err := sql.Open("sqlite", storeURL(path, "ro"))
	if err != nil {
		return err
	}
	defer db.Close()
	var seq int64
	var hash string
	if err := db.QueryRowContext(ctx, "SELECT seq,hash FROM events WHERE session=? ORDER BY seq DESC LIMIT 1", st.Session).Scan(&seq, &hash); err != nil {
		return err
	}
	if seq != st.HeadSeq || hash != st.HeadHash {
		return errors.New("sealing refused: completed journal head/hash differs")
	}
	return nil
}

func normalizeStore(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", storeURL(path, "rw"))
	if err != nil {
		return err
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return checkpointDelete(ctx, conn)
}

func checkpointDelete(ctx context.Context, conn *sql.Conn) error {
	// These PRAGMAs are connection-local: never send them through a pool that
	// could run journal_mode on a different connection. Busy means refusal.
	for _, statement := range []string{"PRAGMA busy_timeout=0", "PRAGMA synchronous=FULL"} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	var mode string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&mode); err != nil {
		return err
	}
	if mode != "delete" {
		return fmt.Errorf("SQLite refused delete journal mode (reported %q)", mode)
	}
	return nil
}
