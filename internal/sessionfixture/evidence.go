package sessionfixture

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/eventlog"
	"github.com/agent-primitives/sessions/wire"
	"google.golang.org/protobuf/proto"
)

type artifactDigest struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}
type fixtureEvidence struct {
	FakeModelCalls   int              `json:"fakeModelCalls"`
	Artifacts        []artifactDigest `json:"artifacts"`
	PublicationCount int              `json:"publicationCount"`
	ReceiptCount     int              `json:"receiptCount"`
	RealModelCalls   *int             `json:"realModelCalls,omitempty"`
	RealLedgerDigest string           `json:"realLedgerDigest,omitempty"`
	RealAttempts     []realAttempt    `json:"realAttempts,omitempty"`
}

func digestBytes(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func existingPrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("absolute existing data directory required")
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if real != path || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("existing nonsymlink mode 0700 directory required")
	}
	return nil
}
func readOnlyDB(path string) (*sql.DB, error) {
	if err := existingPrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	f.Close()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return nil, errors.New("bounded existing regular database required")
	}
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}
func readEvidence(data string) (fixtureEvidence, error) { return readEvidenceScenario(data, "v1") }
func readEvidenceScenario(data, scenario string) (fixtureEvidence, error) {
	ev := fixtureEvidence{Artifacts: []artifactDigest{}}
	if err := checkScenario(data, scenario); err != nil {
		return ev, err
	}
	var err error
	// Keep the inert fake's independent meter visible; it is never evidence of
	// real provider traffic, and an unexpected fake call must not be hidden.
	ev.FakeModelCalls, err = meterCount(filepath.Join(data, "fake-calls.jsonl"))
	if err != nil {
		return ev, err
	}
	if scenario == "v2" {
		ev.RealAttempts, ev.RealLedgerDigest, err = readRealLedger(filepath.Join(data, "real-attempts.db"))
		count := len(ev.RealAttempts)
		ev.RealModelCalls = &count
	}
	if err != nil {
		return ev, err
	}
	path := filepath.Join(data, "publications.db")
	if _, err = os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return ev, nil
	} else if err != nil {
		return ev, err
	}
	db, err := readOnlyDB(path)
	if err != nil {
		return ev, err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return ev, err
	}
	defer tx.Rollback()
	if err = tx.QueryRow("SELECT (SELECT COUNT(*) FROM publications),(SELECT COUNT(*) FROM receipts)").Scan(&ev.PublicationCount, &ev.ReceiptCount); err != nil {
		return ev, err
	}
	if ev.PublicationCount != ev.ReceiptCount || ev.PublicationCount > 10000 {
		return ev, errors.New("publication/receipt atomicity invariant failed")
	}
	rows, err := tx.Query(`SELECT p.session_uid,p.key,p.artifact,p.body,r.fingerprint,r.output FROM publications p JOIN receipts r ON p.session_uid=r.session_uid AND p.key=r.key ORDER BY p.artifact`)
	if err != nil {
		return ev, err
	}
	defer rows.Close()
	total := 0
	for rows.Next() {
		var uid, key, name, fingerprint string
		var raw, output []byte
		if err = rows.Scan(&uid, &key, &name, &raw, &fingerprint, &output); err != nil {
			return ev, err
		}
		total += len(raw) + len(output)
		if total > 8<<20 {
			return ev, errors.New("publication inventory bound exceeded")
		}
		var body struct {
			SessionUID string         `json:"session_uid"`
			Key        string         `json:"key"`
			Output     map[string]any `json:"output"`
		}
		if err = strictJSON(raw, []string{"session_uid", "key", "output"}, &body); err != nil {
			return ev, err
		}
		tuple, _ := json.Marshal([]string{uid, key})
		wantName := digestBytes(tuple) + ".json"
		args := map[string]any{"draft": body.Output["draft"], "destination": body.Output["destination"]}
		callRaw, _ := json.Marshal(struct {
			Tool string         `json:"tool"`
			Args map[string]any `json:"args"`
		}{"publish_release_notes", args})
		if body.SessionUID != uid || body.Key != key || name != wantName || body.Output["simulated"] != true || body.Output["artifact"] != name || len(body.Output) != 4 || fingerprint != digestBytes(callRaw) {
			return ev, errors.New("publication/receipt identity invariant failed")
		}
		if err = validateToolScenario(toolScope(uid), scenarioCall("inventory", "publish_release_notes", args), scenario); err != nil {
			return ev, err
		}
		bodyOutput, _ := json.Marshal(body.Output)
		if string(bodyOutput) != string(output) {
			return ev, errors.New("publication and durable receipt differ")
		}
		ev.Artifacts = append(ev.Artifacts, artifactDigest{Name: name, Digest: digestBytes(raw)})
	}
	if err = rows.Err(); err != nil {
		return ev, err
	}
	if len(ev.Artifacts) != ev.PublicationCount {
		return ev, errors.New("missing publication receipt coverage")
	}
	return ev, nil
}
func readJournalRecords(ctx context.Context, path, uid string) ([]eventlog.Record, error) {
	if !identity(uid, 256) {
		return nil, errors.New("bounded session UID required")
	}
	db, err := readOnlyDB(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var exists string
	if err = tx.QueryRowContext(ctx, "SELECT session FROM sessions WHERE session=?", uid).Scan(&exists); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT seq,prev_hash,hash,fence,event FROM events WHERE session=? ORDER BY seq LIMIT 10001", uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []eventlog.Record{}
	size := 0
	for rows.Next() {
		var r eventlog.Record
		var blob []byte
		if err = rows.Scan(&r.Seq, &r.PrevHash, &r.Hash, &r.Fence, &blob); err != nil {
			return nil, err
		}
		size += len(blob)
		if len(out) >= 10000 || size > 32<<20 {
			return nil, errors.New("journal proof bound exceeded")
		}
		pb := &v1.Event{}
		if err = proto.Unmarshal(blob, pb); err != nil {
			return nil, err
		}
		r.Event = wire.EventFromProto(pb)
		out = append(out, r)
	}
	return out, rows.Err()
}
func fileDigest(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return "absent", nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return "", errors.New("bounded regular file required")
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(f, (64<<20)+1)); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
func journalBytes(path string) ([]string, error) {
	out := []string{}
	for _, p := range []string{path, path + "-wal"} {
		d, err := fileDigest(p)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}
func verifyJournal(ctx context.Context, path, instructions, uid string) (replayProof, error) {
	return verifyJournalScenario(ctx, path, instructions, uid, "v1")
}
func verifyJournalScenario(ctx context.Context, path, instructions, uid, scenario string) (proof replayProof, err error) {
	proof.SessionUID = uid
	defer func() {
		if err != nil {
			proof.Completed = false
			proof.Error = err.Error()
		}
	}()
	if _, err = instructionBytesScenario(instructions, scenario); err != nil {
		return proof, err
	}
	if scenario == "v2" && filepath.Dir(path) != filepath.Dir(instructions) {
		return proof, errors.New("v2 replay journal and instructions must share scenario directory")
	}
	beforeBytes, err := journalBytes(path)
	if err != nil {
		return proof, err
	}
	before, err := readEvidenceScenario(filepath.Dir(path), scenario)
	if err != nil {
		return proof, err
	}
	records, err := readJournalRecords(ctx, path, uid)
	if err != nil {
		return proof, err
	}
	proof, err = verifyReplay(ctx, uid, records, newHarnessScenario(scenario))
	if err != nil {
		return proof, err
	}
	afterRecords, err := readJournalRecords(ctx, path, uid)
	if err != nil {
		return proof, err
	}
	after, err := readEvidenceScenario(filepath.Dir(path), scenario)
	if err != nil {
		return proof, err
	}
	afterBytes, err := journalBytes(path)
	if err != nil {
		return proof, err
	}
	if !reflect.DeepEqual(records, afterRecords) || !reflect.DeepEqual(beforeBytes, afterBytes) || !reflect.DeepEqual(before, after) {
		return proof, errors.New("journal bytes/head/counters/effect inventory changed during strict replay")
	}
	return proof, nil
}
