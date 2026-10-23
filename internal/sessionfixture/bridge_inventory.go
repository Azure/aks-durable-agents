package sessionfixture

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"github.com/agent-primitives/sessions/api"
)

type bridgeInventory struct {
	BridgeOnly       bool             `json:"bridge_only"`
	PublicationCount int              `json:"publication_count"`
	ReceiptCount     int              `json:"receipt_count"`
	Artifacts        []artifactDigest `json:"artifacts"`
}

func inspectBridge(data string) (bridgeInventory, error) {
	inventory := bridgeInventory{BridgeOnly: true, Artifacts: []artifactDigest{}}
	if err := checkBridgeData(data); err != nil {
		return inventory, err
	}
	path := filepath.Join(data, "publications.db")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return inventory, nil
	}
	db, err := bridgeReadOnlyDB(path, false)
	if err != nil {
		return inventory, errors.New("cannot read private demo publication inventory")
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return inventory, err
	}
	defer tx.Rollback()
	if err := tx.QueryRow("SELECT (SELECT COUNT(*) FROM publications),(SELECT COUNT(*) FROM receipts)").Scan(&inventory.PublicationCount, &inventory.ReceiptCount); err != nil {
		return inventory, errors.New("demo publication schema unavailable")
	}
	if inventory.PublicationCount != inventory.ReceiptCount || inventory.PublicationCount > 10000 {
		return inventory, errors.New("demo publication/receipt atomicity mismatch")
	}
	rows, err := tx.Query(`SELECT p.session_uid,p.key,p.artifact,p.body,r.fingerprint,r.output FROM publications p JOIN receipts r ON p.session_uid=r.session_uid AND p.key=r.key ORDER BY p.artifact`)
	if err != nil {
		return inventory, err
	}
	defer rows.Close()
	total := 0
	for rows.Next() {
		var uid, key, name, fingerprint string
		var body, output []byte
		if err := rows.Scan(&uid, &key, &name, &body, &fingerprint, &output); err != nil {
			return inventory, err
		}
		total += len(body) + len(output)
		if total > 8<<20 {
			return inventory, errors.New("demo inventory exceeds bound")
		}
		var out map[string]any
		if strictJSON(output, []string{"local_demo", "artifact", "draft", "destination", "config_sha256"}, &out) != nil {
			return inventory, errors.New("invalid demo receipt")
		}
		call := api.ToolCall{ID: "inspect", IdempotencyKey: key, Tool: bridgeTool, Mediation: api.MediationRequiresApproval, Args: map[string]any{"draft": out["draft"], "destination": out["destination"], "config_sha256": out["config_sha256"]}}
		if validateBridgeTool(toolScope(uid), call) != nil || name != bridgeArtifact(uid, key) || !bridgeReceipt(uid, call, out) {
			return inventory, errors.New("demo receipt identity mismatch")
		}
		raw, err := json.Marshal(struct {
			Tool string         `json:"tool"`
			Args map[string]any `json:"args"`
		}{call.Tool, call.Args})
		if err != nil || fingerprint != digestBytes(raw) {
			return inventory, errors.New("demo receipt fingerprint mismatch")
		}
		var stored struct {
			SessionUID string         `json:"session_uid"`
			Key        string         `json:"key"`
			Output     map[string]any `json:"output"`
		}
		if strictJSON(body, []string{"session_uid", "key", "output"}, &stored) != nil || stored.SessionUID != uid || stored.Key != key || !reflect.DeepEqual(stored.Output, out) {
			return inventory, errors.New("demo publication body mismatch")
		}
		inventory.Artifacts = append(inventory.Artifacts, artifactDigest{Name: name, Digest: bridgeDigest(body)})
	}
	if err := rows.Err(); err != nil {
		return inventory, err
	}
	if len(inventory.Artifacts) != inventory.PublicationCount {
		return inventory, errors.New("demo inventory join mismatch")
	}
	return inventory, nil
}
