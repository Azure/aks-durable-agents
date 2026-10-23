package sessionfixture

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"

	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/harnesswire"
	"google.golang.org/grpc"
)

func runBridgeCLI(ctx context.Context, args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(errOut)
	parse := func() error {
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected demo bridge arguments")
		}
		return nil
	}
	switch args[0] {
	case "bridge-init", "bridge-inspect":
		data := fs.String("data", "", "existing owned mode 0700 demo-only data directory")
		if err := parse(); err != nil {
			return err
		}
		if args[0] == "bridge-init" {
			if err := initBridgeData(*data); err != nil {
				return err
			}
			return json.NewEncoder(out).Encode(map[string]any{"bridge_only": true, "initialized": true})
		}
		inventory, err := inspectBridge(*data)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(inventory)
	case "bridge-harness":
		addr := fs.String("addr", "127.0.0.1:9000", "literal loopback; explicit 0.0.0.0:9000 is private-pod-only")
		model := fs.String("model", "", "explicit target model; not the source's authored model")
		if err := parse(); err != nil {
			return err
		}
		explicit := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "addr" {
				explicit = true
			}
		})
		if !(explicit && *addr == "0.0.0.0:9000") {
			if err := loopback(*addr); err != nil {
				return err
			}
		}
		h := newBridgeHarness(*model)
		descriptor, err := h.Describe(ctx)
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", *addr)
		if err != nil {
			return err
		}
		defer listener.Close()
		server := grpc.NewServer()
		defer server.Stop()
		v1.RegisterHarnessServer(server, harnesswire.NewServer(h))
		if err := json.NewEncoder(out).Encode(map[string]any{"bridge_only": true, "addr": listener.Addr().String(), "harness": descriptor.ID, "version": descriptor.Version, "model": *model, "target_examples": "not_run"}); err != nil {
			return err
		}
		return serveGRPC(ctx, server, listener)
	case "bridge-executor":
		data := fs.String("data", "", "original private demo-only data directory")
		if err := parse(); err != nil {
			return err
		}
		ex, err := openExecutorScenario(filepath.Join(*data, "publications.db"), bridgeScenario)
		if err != nil {
			return err
		}
		defer ex.close()
		socket := filepath.Join(*data, "publish.sock")
		listener, err := listenPrivateSocket(socket)
		if err != nil {
			return err
		}
		defer listener.Close()
		owned, err := os.Lstat(socket)
		if err != nil {
			return err
		}
		defer func() {
			now, err := os.Lstat(socket)
			if err == nil && os.SameFile(owned, now) && now.Mode()&os.ModeSocket != 0 {
				os.Remove(socket)
			}
		}()
		if err := json.NewEncoder(out).Encode(map[string]any{"bridge_only": true, "socket": socket}); err != nil {
			return err
		}
		return serveExecutor(ctx, listener, ex)
	case "bridge-verify":
		data := fs.String("data", "", "original private demo data directory")
		journal := fs.String("journal", "", "original stopped host journal")
		uid := fs.String("session", "", "original session UID")
		model := fs.String("model", "", "original resolved target model")
		config := fs.String("config-sha256", "", "exact Config digest retained when establishing the run")
		reference := fs.String("reference", "", "original opaque producer reference")
		if err := parse(); err != nil {
			return err
		}
		if !identity(*uid, 256) || !identity(*model, 256) || !validBridgeDigest(*config) || !validBridgeDigest(*reference) {
			return errors.New("bridge-verify requires original session/model/config digest/reference")
		}
		proof, replayErr := verifyBridgeJournal(ctx, *data, *journal, *uid, bridgeExpectation{ConfigSHA256: *config, Model: *model, Reference: *reference})
		if err := json.NewEncoder(out).Encode(proof); err != nil {
			return errors.New("cannot write demo bridge replay metadata")
		}
		return replayErr
	default:
		return errors.New("unknown demo bridge role")
	}
}
