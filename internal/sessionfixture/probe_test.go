package sessionfixture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func tcpDialError(err error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9000}, Err: err}
}

// Break caught: an ambiguous dial failure (including EAGAIN's Timeout()==true)
// produces a successful deny proof, or a real connection/timeout changes schema.
func TestNetworkProbeDialOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, expect string
		dialErr      error
		wantOK       bool
		wantProof    bool
	}{
		{"connected allowed", "allowed", nil, true, true},
		{"connected denied mismatch", "denied", nil, false, true},
		{"TCP deadline denied", "denied", tcpDialError(context.DeadlineExceeded), true, true},
		{"TCP deadline allowed mismatch", "allowed", tcpDialError(context.DeadlineExceeded), false, true},
		{"TCP socket deadline", "denied", tcpDialError(os.ErrDeadlineExceeded), true, true},
		{"TCP kernel timeout", "denied", tcpDialError(os.NewSyscallError("connect", syscall.ETIMEDOUT)), true, true},
		{"wrapped TCP timeout", "denied", fmt.Errorf("wrapped: %w", tcpDialError(context.DeadlineExceeded)), true, true},
		{"refused", "denied", tcpDialError(os.NewSyscallError("connect", syscall.ECONNREFUSED)), false, false},
		{"network unreachable", "denied", tcpDialError(syscall.ENETUNREACH), false, false},
		{"host unreachable", "denied", tcpDialError(syscall.EHOSTUNREACH), false, false},
		{"connection reset", "denied", tcpDialError(syscall.ECONNRESET), false, false},
		{"permission denied", "denied", tcpDialError(syscall.EACCES), false, false},
		{"file descriptor limit", "denied", tcpDialError(os.NewSyscallError("socket", syscall.EMFILE)), false, false},
		{"system file descriptor limit", "denied", tcpDialError(syscall.ENFILE), false, false},
		{"buffer exhaustion", "denied", tcpDialError(syscall.ENOBUFS), false, false},
		{"memory exhaustion", "denied", tcpDialError(syscall.ENOMEM), false, false},
		{"local address unavailable", "denied", tcpDialError(syscall.EADDRNOTAVAIL), false, false},
		{"resource temporarily unavailable", "denied", tcpDialError(os.NewSyscallError("socket", syscall.EAGAIN)), false, false},
		{"DNS failure", "denied", tcpDialError(&net.DNSError{Name: "bad.invalid", Err: "no such host", IsNotFound: true}), false, false},
		{"DNS timeout", "denied", tcpDialError(&net.DNSError{Name: "bad.invalid", Err: "i/o timeout", IsTimeout: true, UnwrapErr: context.DeadlineExceeded}), false, false},
		{"bare DNS timeout", "denied", &net.DNSError{Name: "bad.invalid", Err: "i/o timeout", IsTimeout: true}, false, false},
		{"address error", "denied", tcpDialError(&net.AddrError{Err: "invalid address", Addr: "bad"}), false, false},
		{"parse error", "denied", tcpDialError(&net.ParseError{Type: "IP address", Text: "bad"}), false, false},
		{"canceled dial", "denied", tcpDialError(context.Canceled), false, false},
		{"bare deadline", "denied", context.DeadlineExceeded, false, false},
		{"non-TCP timeout", "denied", &net.OpError{Op: "dial", Net: "udp", Err: context.DeadlineExceeded}, false, false},
		{"non-dial timeout", "denied", &net.OpError{Op: "read", Net: "tcp", Err: context.DeadlineExceeded}, false, false},
		{"unknown dial error", "denied", tcpDialError(io.ErrUnexpectedEOF), false, false},
		{"allowed ambiguous failure", "allowed", tcpDialError(syscall.ECONNREFUSED), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := networkProbeWithDial(t.Context(), "10.0.0.1:9000", tc.expect, &out, func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != "10.0.0.1:9000" {
					t.Fatalf("unexpected dial target: %s %s", network, address)
				}
				if tc.dialErr != nil {
					return nil, tc.dialErr
				}
				conn, peer := net.Pipe()
				t.Cleanup(func() { conn.Close(); peer.Close() })
				return conn, nil
			})
			if (err == nil) != tc.wantOK {
				t.Errorf("success = %v, want %v; error: %v", err == nil, tc.wantOK, err)
			}
			if !tc.wantProof {
				if !errors.Is(err, tc.dialErr) {
					t.Errorf("lost underlying dial error: %v", err)
				}
				if out.Len() != 0 {
					t.Errorf("ambiguous failure emitted proof: %s", &out)
				}
				return
			}
			assertProbeProof(t, &out, "10.0.0.1:9000", tc.expect, tc.dialErr == nil)
		})
	}
}

// Break caught: an expired/canceled caller is confused with the probe's own timeout.
func TestNetworkProbeCallerCancellationHasNoProof(t *testing.T) {
	for _, state := range []string{"already canceled", "canceled during dial", "deadline expired"} {
		t.Run(state, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if state == "already canceled" {
				cancel()
			} else if state == "deadline expired" {
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer deadlineCancel()
			}
			var out bytes.Buffer
			err := networkProbeWithDial(ctx, "10.0.0.1:9000", "denied", &out, func(context.Context, string, string) (net.Conn, error) {
				if state == "canceled during dial" {
					cancel()
				}
				return nil, tcpDialError(context.DeadlineExceeded)
			})
			if !errors.Is(err, ctx.Err()) || err == nil {
				t.Fatalf("want caller error %v, got %v", ctx.Err(), err)
			}
			if out.Len() != 0 {
				t.Fatalf("caller cancellation emitted proof: %s", &out)
			}
		})
	}
}

// Break caught: the probe loses its own three-second bound or rejects that
// deadline as caller cancellation. No external network or DNS is needed.
func TestNetworkProbeBoundedDeadline(t *testing.T) {
	start := time.Now()
	var out bytes.Buffer
	err := networkProbeWithDial(t.Context(), "10.0.0.1:9000", "denied", &out, func(ctx context.Context, network, address string) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		if !ok || deadline.Before(start) || deadline.After(start.Add(3*time.Second+100*time.Millisecond)) {
			t.Fatalf("dial is not bounded to three seconds: %v, present=%v", deadline, ok)
		}
		<-ctx.Done()
		return nil, tcpDialError(ctx.Err())
	})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 2900*time.Millisecond {
		t.Fatalf("probe expired before its three-second bound: %v", elapsed)
	}
	assertProbeProof(t, &out, "10.0.0.1:9000", "denied", false)
}

func assertProbeProof(t *testing.T, out *bytes.Buffer, address, expect string, allowed bool) {
	t.Helper()
	var got map[string]any
	decoder := json.NewDecoder(out)
	if err := decoder.Decode(&got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"address": address, "allowed": allowed, "expect": expect, "tcpOnly": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("proof = %#v, want %#v", got, want)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("unexpected output after proof: %v", err)
	}
}
