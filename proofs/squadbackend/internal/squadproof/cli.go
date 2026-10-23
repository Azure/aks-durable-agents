//go:build squadproof

package squadproof

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/client"

	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/harnesswire"
	"google.golang.org/grpc"
)

// RunCLI exposes bounded proof fixtures, not a general SquadBackend facade.
// Reopening retained data requires quiescent writers; online recovery is unsupported.
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
	case "broker", "scenario", "inspect", "replay":
		data := fs.String("data", "", "existing private proof directory")
		var server, name, operation, decision string
		if args[0] == "broker" {
			fs.StringVar(&operation, "operation", "", "explicit synthetic decision target")
			fs.StringVar(&decision, "decision", "", "explicit synthetic approval JSON")
		}
		var stopped bool
		if args[0] == "broker" || args[0] == "scenario" {
			fs.StringVar(&server, "server", "", "literal loopback Sessions server")
		}
		if args[0] == "scenario" {
			fs.StringVar(&name, "case", "", "happy, deny or queue (fresh case only)")
		}
		if args[0] == "inspect" || args[0] == "replay" {
			fs.BoolVar(&stopped, "writers-stopped", false, "caller has stopped all writers")
		}
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || !*proofOnly || !privateDirectory(*data) {
			return ErrInvalid
		}
		var p Proof
		var err error
		switch args[0] {
		case "scenario":
			p, err = RunCase(ctx, name, *data, server)
		case "inspect", "replay":
			if !stopped {
				return ErrInvalid
			}
			p, err = snapshotProof(ctx, *data, args[0] == "replay")
		case "broker":
			target, e := proofServer(server)
			if e != nil {
				return e
			}
			l, e := existingLedger(*data)
			if e != nil {
				return e
			}
			defer l.Close()
			c, e := client.Dial(target)
			if e != nil {
				return e
			}
			defer c.Close()
			before, e := l.Counts(ctx)
			if e != nil {
				return e
			}
			w := &Worker{Ledger: l, Sessions: c}
			var action error
			if decision != "" {
				var d api.ApprovalDecision
				decoder := json.NewDecoder(strings.NewReader(decision))
				decoder.DisallowUnknownFields()
				if _, _, e = canonical([]byte(decision)); e != nil || !identity(operation) || decoder.Decode(&d) != nil {
					return ErrInvalid
				}
				action = w.Decide(ctx, operation, d)
			} else {
				if operation != "" {
					return ErrInvalid
				}
				action = w.Reconcile(ctx)
			}
			if action != nil && !errors.Is(action, ErrHeld) && (decision != "" || !errors.Is(action, ErrNotFound)) {
				return action
			}
			p, err = ledgerProof(ctx, l)
			p.Outcome = "action"
			if p.Counts == before || errors.Is(action, ErrNotFound) {
				p.Outcome = "idle"
			}
			if errors.Is(action, ErrHeld) {
				p.Outcome = "held"
			}
		}
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(p)
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

// proofServer rejects resolvers and URL features before an SDK dial can occur.
func proofServer(raw string) (string, error) {
	if strings.HasPrefix(raw, "http://") {
		u, err := url.Parse(raw)
		if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
			return "", ErrInvalid
		}
		raw = u.Host
	}
	if !localAddress(raw, false) {
		return "", ErrInvalid
	}
	return raw, nil
}
