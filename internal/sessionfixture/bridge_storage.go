package sessionfixture

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func checkBridgeData(data string) error {
	raw, err := readOwnedFile(filepath.Join(data, "scenario.json"), 1024)
	if err != nil || string(raw) != bridgeMarker {
		return errors.New("demo bridge requires its original private source-demo-v1 data")
	}
	return nil
}
func writeBridgeFile(path string, raw []byte) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("demo bridge requires new private files")
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	return f.Sync()
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
		return errors.New("demo bridge initialization requires an owned empty private directory")
	}
	socket := filepath.Join(data, "publish.sock")
	if len(socket) > 103 {
		return errors.New("demo bridge Unix socket path exceeds bound")
	}
	if err := writeBridgeFile(filepath.Join(data, "scenario.json"), []byte(bridgeMarker)); err != nil {
		return err
	}
	config := map[string]any{"version": 1, "executors": []any{map[string]any{"name": "demo-local-publish", "type": "unix", "socket": socket, "timeout_ms": 30000}}, "tools": []any{map[string]any{"harness": bridgeHarnessID, "tool": bridgeTool, "executor": "demo-local-publish", "durable_dedup": true}}}
	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	if err := writeBridgeFile(filepath.Join(data, "tools.json"), append(raw, '\n')); err != nil {
		return err
	}
	dir, err := os.Open(data)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
