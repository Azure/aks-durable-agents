package modeltransport

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func v2PolicyConfig(t *testing.T) (string, string) {
	t.Helper()
	path, ledger := policyConfig(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `"version":1`, `"version":2,"maxAttempts":3`, 1))
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path, ledger
}

func TestPolicyV2ThreeAttemptsSurviveRestart(t *testing.T) {
	path, ledger := v2PolicyConfig(t)
	var sends atomic.Int32
	for i := 0; i < 4; i++ {
		p, err := OpenPolicyFile(path)
		if err != nil {
			t.Fatal(err)
		}
		c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) { sends.Add(1); io.WriteString(w, structuredSuccess()) }, goodCredential())
		err = boundedSend(c, target, structuredChat(fmt.Sprint(i), testFormat, false))
		if closeErr := p.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if (i < 3) != (err == nil) {
			t.Fatalf("attempt%d: %v", i+1, err)
		}
	}
	n, outcome, _, _, _ := ledgerRows(t, ledger)
	if sends.Load() != 3 || n != 3 || outcome != "succeeded" {
		t.Fatalf("cap lost across reopen: sends%d rows%d %s", sends.Load(), n, outcome)
	}
}

func TestPolicyV2RequiresExplicitThreeAndReservesWholeBudget(t *testing.T) {
	for _, tc := range []struct {
		name, from, to string
		ok             bool
	}{
		{"valid", `"maxAttempts":3`, `"maxAttempts":3`, true},
		{"missing", `"maxAttempts":3,`, ``, false},
		{"two", `"maxAttempts":3`, `"maxAttempts":2`, false},
		{"four", `"maxAttempts":3`, `"maxAttempts":4`, false},
		{"null", `"maxAttempts":3`, `"maxAttempts":null`, false},
		{"v1-field", `"version":2`, `"version":1`, false},
		{"above-budget", `500000`, `162760415`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, _ := v2PolicyConfig(t)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data = []byte(strings.Replace(string(data), tc.from, tc.to, 1))
			if tc.name == "above-budget" {
				data = []byte(strings.Replace(string(data), `100000`, `1`, 1))
			}
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			p, err := OpenPolicyFile(path)
			if p != nil {
				p.Close()
			}
			if tc.ok != (err == nil) {
				t.Fatalf("policy accepted=%t error=%v", tc.ok, err)
			}
		})
	}
	path, _ := v2PolicyConfig(t)
	data, _ := os.ReadFile(path)
	data = []byte(strings.Replace(strings.Replace(string(data), `100000`, `1`, 1), `500000`, `162760414`, 1))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := OpenPolicyFile(path)
	if err != nil {
		t.Fatalf("exact integer reservation boundary refused: %v", err)
	}
	p.Close()
}

func TestPolicyV2CannotUpgradeExistingLedger(t *testing.T) {
	p, path, ledger := openTestPolicy(t)
	p.Close()
	before, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if err = os.WriteFile(path, []byte(strings.Replace(string(data), `"version":1`, `"version":2,"maxAttempts":3`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	p, err = OpenPolicyFile(path)
	if p != nil {
		p.Close()
	}
	if err == nil {
		t.Fatal("upgraded existing run budget")
	}
	after, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("refused upgrade changed ledger")
	}
}

func TestPolicyV2UnknownOutcomeStopsDespiteSpareBudget(t *testing.T) {
	path, ledger := v2PolicyConfig(t)
	p, err := OpenPolicyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var sends atomic.Int32
	c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) { sends.Add(1); io.WriteString(w, `{"choices":[]}`) }, goodCredential())
	if err = boundedSend(c, target, chat("first", false)); err == nil {
		t.Fatal("unknown completion accepted")
	}
	if err = boundedSend(c, target, chat("second", false)); err == nil {
		t.Fatal("spare count bypassed unknown stop")
	}
	n, outcome, _, _, _ := ledgerRows(t, ledger)
	if sends.Load() != 1 || n != 1 || outcome != "unknown" {
		t.Fatalf("unknown stop lost: %d %d %s", sends.Load(), n, outcome)
	}
}
