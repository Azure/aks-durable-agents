package modeltransport

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestPolicyRejectsCaseVariantSchemaKeys(t *testing.T) {
	config, _ := policyConfig(t)
	data, _ := os.ReadFile(config)
	os.WriteFile(config, []byte(strings.Replace(string(data), `"version":1`, `"version":1,"Version":1`, 1)), 0600)
	if p, err := OpenPolicyFile(config); err == nil {
		p.Close()
		t.Error("case variant policy key accepted")
	}
	p, _, _ := openTestPolicy(t)
	c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) {
		t.Error("sent non-schema key")
		io.WriteString(w, usageResponse)
	}, goodCredential())
	body := `{"model":"test-deployment","messages":[{"Role":"user","content":"x"}]}`
	if err := boundedSend(c, target, body); err == nil {
		t.Fatal("case variant message key accepted")
	}
}

func TestPolicyFullContextUTF8Bound(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		allow      bool
	}{
		{"exact", chat(strings.Repeat("x", 7868), false), true},
		{"one byte over", chat(strings.Repeat("x", 7869), false), false},
		{"UTF8 bytes not runes", chat(strings.Repeat("é", 4000), false), false},
		{"entire context", `{"model":"test-deployment","messages":[{"role":"system","content":"` + strings.Repeat("s", 4000) + `"},{"role":"user","content":"` + strings.Repeat("u", 4000) + `"}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _ := openTestPolicy(t)
			c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) {
				if !tc.allow {
					t.Error("sent over bound")
				}
				// Connection: close lets an early response race the remaining TLS writes.
				// Consume the complete POST before returning the success fixture.
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Errorf("read request body: %v", err)
					return
				}
				io.WriteString(w, usageResponse)
			}, goodCredential())
			err := boundedSend(c, target, tc.body)
			if (err == nil) != tc.allow {
				t.Fatalf("allow=%v err=%v", tc.allow, err)
			}
		})
	}
}

func TestPolicyRejectsLedgerSidecarSymlink(t *testing.T) {
	config, ledger := policyConfig(t)
	if err := os.Symlink("/dev/null", ledger+"-journal"); err != nil {
		t.Fatal(err)
	}
	if p, err := OpenPolicyFile(config); err == nil {
		p.Close()
		t.Fatal("unsafe sidecar accepted")
	}
}
