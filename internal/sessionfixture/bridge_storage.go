package sessionfixture

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

func checkBridgeData(data string) error {
	raw, err := readOwnedFile(filepath.Join(data, "scenario.json"), 1024)
	if err != nil || string(raw) != bridgeMarker {
		return errors.New("demo bridge requires its original private source-demo-v1 data")
	}
	return nil
}
func initBridgeData(data string) error {
	if err := existingPrivateDirectory(data); err != nil {
		return err
	}
	if err := privateParent(data); err != nil {
		return err
	}
	entries, err := os.ReadDir(data)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("demo bridge requires new empty private data")
	}
	socket := filepath.Join(data, "publish.sock")
	if len(socket) > 103 {
		return errors.New("demo socket path exceeds bound")
	}
	raw, err := json.Marshal(map[string]any{"version": 1, "executors": []any{map[string]any{"name": "demo-local-publish", "type": "unix", "socket": socket}}, "tools": []any{map[string]any{"harness": bridgeHarnessID, "tool": bridgeTool, "executor": "demo-local-publish", "durable_dedup": true}}})
	if err != nil {
		return err
	}
	for name, raw := range map[string][]byte{"scenario.json": []byte(bridgeMarker), "tools.json": raw} {
		if err := freezeFile(filepath.Join(data, name), raw); err != nil {
			return err
		}
	}
	return nil
}
