package host

import (
	"strings"
	"testing"

	"github.com/agent-primitives/sessions/authn"
)

func TestSessionsAndHealthListenersRequireLoopback(t *testing.T) {
	for _, mode := range []authn.Mode{authn.Off, authn.Required} {
		for _, addr := range []string{"0.0.0.0:8080", "[::]:8080", "192.0.2.1:8080", "sessions.agents.svc.cluster.local:8080"} {
			for _, listener := range []string{"sessions", "health"} {
				t.Run(string(mode)+"/"+listener+"/"+addr, func(t *testing.T) {
					f := newHostFixture(t)
					c := f.config
					c.Mode = mode
					if listener == "sessions" {
						c.Addr = addr
					} else {
						c.HealthAddr = addr
					}
					if err := c.validate(); err == nil || !strings.Contains(err.Error(), "literal loopback") {
						t.Fatalf("non-loopback listener must fail before startup: %v", err)
					}
				})
			}
		}
	}
}
