package sessionfixture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/harnesswire"
	"google.golang.org/grpc"
)

const FrozenInstructions = frozenInstructions

func newREFERENCE() *releaseNotesHarness { return newHarness(FrozenInstructions) }

// RunCLI has no startup connection or service composition. Exactly one explicitly
// selected bounded role runs; the unchanged stock daemon owns Sessions.
func RunCLI(ctx context.Context, args []string, out, errOut io.Writer) error {
	return runCLI(ctx, args, out, errOut)
}
func runCLI(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) > 0 && strings.HasPrefix(args[0], "bridge-") {
		return runBridgeCLI(ctx, args, out, errOut)
	}
	if len(args) == 0 {
		return errors.New("commands: init, harness, actor-harness, fake, executor, placement-evidence, evidence, verify-replay, verify-loop, storage-proof, network-probe, resolve-intent")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(errOut)
	parse := func() error {
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		return nil
	}
	switch args[0] {
	case "init":
		scenario := fs.String("scenario", "v1", "v1 frozen or explicit v2 real-model scenario")
		data := fs.String("data", "", "absolute private data directory")
		socket := fs.String("socket", "", "executor socket (v1 /run/reference/publish.sock; v2 DATA/publish.sock)")
		if err := parse(); err != nil {
			return err
		}
		if *socket == "" {
			*socket = "/run/reference/publish.sock"
			if *scenario == "v2" {
				*socket = filepath.Join(*data, "publish.sock")
			}
		}
		if err := initDataScenario(*data, *socket, *scenario); err != nil {
			return err
		}
		info, err := pathProof(*data)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"initialized": true, "data": *data, "uid": os.Getuid(), "gid": os.Getgid(), "mode": info.Mode})
	case "harness":
		scenario := fs.String("scenario", "v1", "v1 frozen or explicit v2 real-model scenario")
		addr := fs.String("addr", "127.0.0.1:9000", "loopback gRPC address; v2 explicitly allows 0.0.0.0:9000")
		instructions := fs.String("instructions", "", "frozen instructions file")
		node := fs.String("node-name", "", "v2 fixture pod node name")
		pod := fs.String("pod-uid", "", "v2 fixture pod UID")
		if err := parse(); err != nil {
			return err
		}
		explicitAddr := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "addr" {
				explicitAddr = true
			}
		})
		if err := harnessAddress(*addr, *scenario, explicitAddr); err != nil {
			return err
		}
		if _, err := instructionBytesScenario(*instructions, *scenario); err != nil {
			return err
		}
		if *scenario == "v2" {
			if err := writePlacement(filepath.Dir(*instructions), *node, *pod); err != nil {
				return err
			}
		} else if *node != "" || *pod != "" {
			return errors.New("placement flags require scenario v2")
		}
		listener, err := net.Listen("tcp", *addr)
		if err != nil {
			return err
		}
		defer listener.Close()
		server := grpc.NewServer()
		defer server.Stop()
		h := newHarnessScenario(*scenario)
		v1.RegisterHarnessServer(server, harnesswire.NewServer(h))
		version := hostVersion
		if *scenario == "v2" {
			version = v2HostVersion
		}
		if err = json.NewEncoder(out).Encode(map[string]any{"addr": listener.Addr().String(), "harness": "release-notes", "hostVersion": version, "resumability": "STATELESS_REPLAY"}); err != nil {
			return err
		}
		return serveGRPC(ctx, server, listener)
	case "placement-evidence":
		data := fs.String("data", "", "owned private host data directory")
		if err := parse(); err != nil {
			return err
		}
		raw, err := readOwnedFile(filepath.Join(*data, "substrate-placement.json"), 65536)
		if err != nil {
			return err
		}
		if !json.Valid(raw) {
			return errors.New("invalid private placement JSON")
		}
		return json.NewEncoder(out).Encode(json.RawMessage(raw))
	case "actor-harness":
		addr := fs.String("addr", "0.0.0.0:80", "actor harness port80; literal loopback is allowed for offline tests")
		check := fs.Bool("check", false, "print the frozen actor capability descriptor without starting a listener")
		if err := parse(); err != nil {
			return err
		}
		return runActorHarness(ctx, *addr, *check, out)
	case "fake":
		addr := fs.String("addr", "127.0.0.1:9001", "literal loopback HTTP address")
		ledger := fs.String("ledger", "", "absolute durable fake call meter")
		if err := parse(); err != nil {
			return err
		}
		if err := loopback(*addr); err != nil {
			return err
		}
		handler, err := newFakeHandler(*ledger)
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", *addr)
		if err != nil {
			return err
		}
		defer listener.Close()
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
		if err = json.NewEncoder(out).Encode(map[string]string{"addr": listener.Addr().String()}); err != nil {
			return err
		}
		done := make(chan error, 1)
		go func() { done <- server.Serve(listener) }()
		select {
		case <-ctx.Done():
			server.Close()
			<-done
			return nil
		case err = <-done:
			return err
		}
	case "executor":
		scenario := fs.String("scenario", "v1", "v1 frozen or explicit v2 real-model scenario")
		socket := fs.String("socket", "", "private Unix socket; v2 defaults to database directory/publish.sock")
		database := fs.String("database", "", "absolute durable SQLite publication and receipt DB")
		if err := parse(); err != nil {
			return err
		}
		if *scenario == "v2" {
			shared := filepath.Join(filepath.Dir(*database), "publish.sock")
			if *socket == "" {
				*socket = shared
			}
			if *socket != shared {
				return errors.New("v2 executor requires shared data/publish.sock")
			}
		}
		ex, err := openExecutorScenario(*database, *scenario)
		if err != nil {
			return err
		}
		defer ex.close()
		listener, err := listenPrivateSocket(*socket)
		if err != nil {
			return err
		}
		defer listener.Close()
		owned, err := os.Lstat(*socket)
		if err != nil {
			return err
		}
		defer func() {
			now, err := os.Lstat(*socket)
			if err == nil && os.SameFile(owned, now) && now.Mode()&os.ModeSocket != 0 {
				os.Remove(*socket)
			}
		}()
		if err = json.NewEncoder(out).Encode(map[string]string{"socket": *socket}); err != nil {
			return err
		}
		return serveExecutor(ctx, listener, ex)
	case "evidence":
		scenario := fs.String("scenario", "v1", "v1 frozen or explicit v2 real-model scenario")
		data := fs.String("data", "", "absolute private data directory")
		if err := parse(); err != nil {
			return err
		}
		ev, err := readEvidenceScenario(*data, *scenario)
		if err != nil {
			return err
		}
		return encodeEvidence(out, ev, *scenario)
	case "verify-replay":
		scenario := fs.String("scenario", "v1", "v1 frozen or explicit v2 real-model scenario")
		journal := fs.String("journal", "", "existing journal DB")
		instructions := fs.String("instructions", "", "frozen instructions file")
		uid := fs.String("session", "", "session UID")
		if err := parse(); err != nil {
			return err
		}
		proof, replayErr := verifyJournalScenario(ctx, *journal, *instructions, *uid, *scenario)
		if err := json.NewEncoder(out).Encode(proof); err != nil {
			return err
		}
		return replayErr
	case "verify-loop":
		phase := fs.String("phase", "", "park or complete")
		data := fs.String("data", "", "absolute durable data directory")
		server := fs.String("server", "127.0.0.1:8080", "literal loopback Sessions address")
		uid := fs.String("session", "", "parked session UID for completion")
		if err := parse(); err != nil {
			return err
		}
		if err := loopback(*server); err != nil {
			return err
		}
		if *phase != "park" && *phase != "complete" {
			return errors.New("phase must be park or complete")
		}
		bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		proof, err := verifyLoop(bounded, *phase, *data, *server, *uid)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(proof)
	case "resolve-intent":
		scenario := fs.String("scenario", "v2", "v2 lost-Create reconciliation only")
		journal := fs.String("journal", "", "existing journal DB")
		intent := fs.String("intent", "", "recorded release-UUID session name")
		if err := parse(); err != nil {
			return err
		}
		if *scenario != "v2" {
			return errors.New("resolve-intent requires scenario v2")
		}
		return resolveIntent(ctx, *journal, *intent, out)
	case "network-probe":
		address := fs.String("address", "", "TCP-only probe host:port")
		expect := fs.String("expect", "", "allowed or denied")
		if err := parse(); err != nil {
			return err
		}
		return networkProbe(ctx, *address, *expect, out)
	case "storage-proof":
		data := fs.String("data", "/data", "data path")
		socket := fs.String("socket", "/run/reference/publish.sock", "socket path")
		if err := parse(); err != nil {
			return err
		}
		paths := []storagePath{}
		for _, path := range []string{*data, filepath.Dir(*socket), "/tmp"} {
			proof, err := pathProof(path)
			if err != nil {
				return err
			}
			paths = append(paths, proof)
		}
		return json.NewEncoder(out).Encode(map[string]any{"uid": os.Getuid(), "gid": os.Getgid(), "paths": paths})
	default:
		return errors.New("unknown command: " + args[0])
	}
}
func serveGRPC(ctx context.Context, server *grpc.Server, listener net.Listener) error {
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		server.Stop()
		<-done
		return nil
	case err := <-done:
		return err
	}
}
func loopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("literal loopback host:port required")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("only literal loopback addresses are allowed")
	}
	return nil
}
func instructionBytes(path string) ([]byte, error) { return instructionBytesScenario(path, "v1") }
func instructionBytesScenario(path, scenario string) ([]byte, error) {
	if err := validScenario(scenario); err != nil {
		return nil, err
	}
	if scenario == "v2" {
		if err := checkScenario(filepath.Dir(path), scenario); err != nil {
			return nil, err
		}
		raw, err := readOwnedFile(path, 65536)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(raw, []byte(v2Instructions)) {
			return nil, errors.New("frozen v2 instructions changed; refusing recovery")
		}
		return raw, nil
	} else if _, err := os.Lstat(filepath.Join(filepath.Dir(path), "scenario.json")); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("frozen v1 instructions cannot consume marked scenario data")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("regular instruction file required")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, []byte(scenarioInstructions(scenario))) {
		return nil, errors.New("frozen REFERENCE instructions changed; refusing recovery")
	}
	return raw, nil
}
func initData(data, socket string) error { return initDataScenario(data, socket, "v1") }
func initDataScenario(data, socket, scenario string) error {
	if err := validScenario(scenario); err != nil {
		return err
	}
	// The one-shot initializer mounts PVC root at /mnt; application pods mount
	// the new subtree at /data. Record the fixed runtime socket, not a Job-local
	// mount name. Local tests may keep their data/socket in the same directory.
	if scenario == "v2" && socket != filepath.Join(data, "publish.sock") && socket != "/data/publish.sock" {
		return errors.New("v2 init requires the shared data/publish.sock runtime path")
	}
	if err := initScenarioMarker(data, scenario); err != nil {
		return err
	}
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || len(socket) > 103 {
		return errors.New("absolute bounded socket path required")
	}
	tools := map[string]any{"version": 1, "executors": []any{map[string]any{"name": "reference-publish", "type": "unix", "socket": socket, "timeout_ms": 30000}}, "tools": []any{map[string]any{"harness": "release-notes", "tool": "publish_release_notes", "executor": "reference-publish", "durable_dedup": true}}}
	raw, err := json.Marshal(tools)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	for _, file := range []struct {
		name string
		raw  []byte
	}{{"instructions.txt", []byte(scenarioInstructions(scenario))}, {"tools.json", raw}} {
		if err = freezeFile(filepath.Join(data, file.name), file.raw); err != nil {
			return err
		}
	}
	return nil
}
func freezeFile(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if errors.Is(err, os.ErrExist) {
		if _, err = privateFile(path); err != nil {
			return err
		}
		f, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		old, err := io.ReadAll(io.LimitReader(f, int64(len(raw)+1)))
		if err != nil {
			return err
		}
		if !bytes.Equal(old, raw) {
			return errors.New("frozen fixture file changed; refusing recovery")
		}
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

type storagePath struct {
	Path string `json:"path"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	Mode string `json:"mode"`
}

func pathProof(path string) (storagePath, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return storagePath{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 {
		return storagePath{}, errors.New("nonsymlink Unix storage required")
	}
	return storagePath{path, st.Uid, st.Gid, info.Mode().Perm().String()}, nil
}
