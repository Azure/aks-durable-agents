package main

import (
	"net"
	"testing"
)

func TestTCPProbeHasPositiveAndNegativeControls(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	defer ln.Close()
	if err = probe(address, "allowed"); err != nil {
		t.Fatal(err)
	}
	if err = probe(address, "denied"); err == nil {
		t.Fatal("live listener reported denied")
	}
	ln.Close()
	if err = probe(address, "denied"); err != nil {
		t.Fatal(err)
	}
	if err = probe(address, "allowed"); err == nil {
		t.Fatal("closed listener reported allowed")
	}
	for _, address := range []string{"example.com:443", "127.0.0.1:0", "127.0.0.1:99999"} {
		if probe(address, "denied") == nil {
			t.Fatalf("invalid destination treated as denial: %s", address)
		}
	}
	if probe("127.0.0.1:1", "unknown") == nil {
		t.Fatal("unknown expectation accepted")
	}
}
