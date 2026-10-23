//go:build squadproof

package squadproof

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

// RunCLI exposes serving fixtures, not a SquadBackend facade or automatic broker.
// The command is excluded from default builds and all published images.
func RunCLI(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return ErrInvalid
	}
	if args[0] == "host" {
		cfg, err := HostConfig(args[1:])
		if err != nil {
			return err
		}
		life, cancel := context.WithCancel(ctx)
		defer cancel()
		var readyErr error
		err = RunHost(life, cfg, func(address string) {
			readyErr = json.NewEncoder(out).Encode(map[string]string{"role": "host", "address": address, "package": proofDigest()})
			if readyErr != nil {
				cancel()
			}
		})
		if err != nil {
			return err
		}
		return readyErr
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	proofOnly := fs.Bool("proof-only", false, "explicit isolated proof opt-in")
	switch args[0] {
	case "harness":
		role := fs.String("role", "", "lead or member")
		address := fs.String("addr", "127.0.0.1:9000", "literal loopback harness listener")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || !*proofOnly || (*role != "lead" && *role != "member") || !localAddress(*address, true) {
			return ErrInvalid
		}
		listener, err := net.Listen("tcp", *address)
		if err != nil {
			return err
		}
		defer listener.Close()
		server := grpc.NewServer(grpc.WaitForHandlers(true))
		defer server.Stop()
		v1.RegisterHarnessServer(server, harnesswire.NewServer(NewHarness(*role, proofDigest())))
		if err = json.NewEncoder(out).Encode(map[string]string{"role": *role, "address": listener.Addr().String(), "package": proofDigest()}); err != nil {
			return err
		}
		done := make(chan error, 1)
		go func() { done <- server.Serve(listener) }()
		select {
		case err = <-done:
			return err
		case <-ctx.Done():
			server.Stop()
			err = <-done
			if errors.Is(err, grpc.ErrServerStopped) {
				return nil
			}
			return err
		}
	case "executor":
		data := fs.String("data", "", "existing private proof directory")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || !*proofOnly || !privateDirectory(*data) {
			return ErrInvalid
		}
		socket := filepath.Join(*data, "tools.sock")
		if len(socket) > 103 {
			return ErrInvalid
		}
		if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
			return ErrHeld
		}
		l, err := OpenLedger(filepath.Join(*data, "proof.db"))
		if err != nil {
			return err
		}
		defer l.Close()
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
		if err != nil {
			return err
		}
		defer listener.Close()
		if err = os.Chmod(socket, 0600); err != nil {
			return err
		}
		if err = json.NewEncoder(out).Encode(map[string]string{"role": "executor", "socket": socket}); err != nil {
			return err
		}
		return ServeExecutor(ctx, listener, l)
	default:
		return ErrInvalid
	}
}
