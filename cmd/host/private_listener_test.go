package main

import "testing"

func TestTrustedNetworkSessionsFlagIsUnsupported(t *testing.T) {
	for _, flag := range []string{"-sessions-trusted-network", "-sessions-trusted-network=true", "-sessions-trusted-network=false"} {
		t.Run(flag, func(t *testing.T) {
			if _, err := parse([]string{flag, "-addr=0.0.0.0:8080", "-auth-mode=off", "-tls-cert=/tls/tls.crt", "-tls-key=/tls/tls.key"}); err == nil {
				t.Fatal("removed wildcard listener option accepted")
			}
		})
	}
}
