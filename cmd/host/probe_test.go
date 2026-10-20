package main

import (
	"net"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestHealthProbeRunsWithoutIdentityOrState(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "host")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build host: %v %s", err, out)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	defer ln.Close()
	for _, tc := range []struct {
		address string
		ok      bool
	}{
		{address, true}, {"localhost:8081", false}, {"0.0.0.0:8081", false}, {"10.0.0.1:8081", false}, {"127.0.0.1:0", false}, {"127.0.0.1:08081", false}, {"127.0.0.1:65536", false},
	} {
		t.Run(tc.address, func(t *testing.T) {
			cmd := exec.Command(binary, "health-probe", tc.address)
			cmd.Dir = t.TempDir()
			if out, err := cmd.CombinedOutput(); (err == nil) != tc.ok {
				t.Fatalf("health probe accepted=%t: %v %s", tc.ok, err, out)
			}
		})
	}
	if err = ln.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(binary, "health-probe", address).CombinedOutput(); err == nil {
		t.Fatalf("closed listener healthy: %s", out)
	}
}
