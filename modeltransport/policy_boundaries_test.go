package modeltransport

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// Missing text and an explicit zero cap are unsupported, not safe defaults.
func TestPolicyClosedRequestRequiresTextAndValidExplicitCap(t *testing.T) {
	for _, body := range []string{
		`{"model":"test-deployment","messages":[{"role":"user"}]}`,
		`{"model":"test-deployment","messages":[{"role":"user","content":"x"}],"max_completion_tokens":0}`,
		`{"model":"test-deployment","messages":[{"role":"user","content":"x"}],"stream_options":{}}`,
	} {
		t.Run(body, func(t *testing.T) {
			p, _, _ := openTestPolicy(t)
			c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) {
				t.Error("sent unsupported form")
				io.WriteString(w, usageResponse)
			}, goodCredential())
			if err := boundedSend(c, target, body); err == nil {
				t.Fatal("unsupported request accepted")
			}
		})
	}
}

func TestPolicySSERequiresCompleteTerminatorEvent(t *testing.T) {
	p, _, ledger := openTestPolicy(t)
	c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "data: "+usageResponse+"\n\ndata: [DONE]\n")
	}, goodCredential())
	if err := boundedSend(c, target, chat("x", true)); err == nil {
		t.Fatal("truncated DONE event succeeded")
	}
	_, outcome, _, _, _ := ledgerRows(t, ledger)
	if outcome != "unknown" {
		t.Fatal(outcome)
	}
}

func TestPolicyRejectsNonSuccessFinishReason(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			p, _, ledger := openTestPolicy(t)
			c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) {
				body := `{"choices":[{"finish_reason":"length"}],"usage":{"prompt_tokens":12,"completion_tokens":4096}}`
				if stream {
					body = "data: " + body + "\n\ndata: [DONE]\n\n"
				}
				io.WriteString(w, body)
			}, goodCredential())
			if err := boundedSend(c, target, chat("x", stream)); err == nil {
				t.Fatal("truncated generation succeeded")
			}
			_, outcome, _, _, _ := ledgerRows(t, ledger)
			if outcome == "succeeded" {
				t.Fatal(outcome)
			}
		})
	}
}

func TestPolicyReservationExactBoundary(t *testing.T) {
	for _, tc := range []struct {
		out   string
		valid bool
	}{{"243940625", true}, {"243940626", false}} {
		t.Run(tc.out, func(t *testing.T) {
			config, _ := policyConfig(t)
			data, _ := os.ReadFile(config)
			os.WriteFile(config, []byte(strings.Replace(string(data), "500000", tc.out, 1)), 0600)
			p, err := OpenPolicyFile(config)
			if (err == nil) != tc.valid {
				t.Fatalf("boundary valid=%v err=%v", tc.valid, err)
			}
			if p != nil {
				p.Close()
			}
		})
	}
}

// A crash or uncertain attempt is a durable stop across a fresh policy handle.
func TestPolicyCrashAndConcurrentAttemptStop(t *testing.T) {
	for _, prior := range []string{"reserved", "dispatching", "failed", "unknown"} {
		t.Run(prior, func(t *testing.T) {
			p, config, ledger := openTestPolicy(t)
			p.Close()
			db, err := sql.Open("sqlite", ledger)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec("INSERT INTO model_attempts(request_hash,started_at,outcome) VALUES('crash','now',?)", prior)
			db.Close()
			if err != nil {
				t.Fatal(err)
			}
			p, err = OpenPolicyFile(config)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			c, target := boundedFixture(t, p, func(http.ResponseWriter, *http.Request) { t.Error("sent after durable stop") }, goodCredential())
			if err = boundedSend(c, target, chat("x", false)); err == nil {
				t.Fatal("prior unresolved/error ignored")
			}
		})
	}
	p, config, ledger := openTestPolicy(t)
	other, err := OpenPolicyFile(config)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		io.WriteString(w, usageResponse)
	}, goodCredential())
	defer close(release)
	done := make(chan error, 1)
	go func() { done <- boundedSend(c, target, chat("first", false)) }()
	<-entered
	second, secondTarget := boundedFixture(t, other, func(http.ResponseWriter, *http.Request) { t.Error("parallel send") }, goodCredential())
	if err = boundedSend(second, secondTarget, chat("other", false)); err == nil {
		t.Fatal("parallel unresolved attempt allowed")
	}
	n, outcome, _, _, _ := ledgerRows(t, ledger)
	if n != 1 || outcome != "dispatching" {
		t.Fatalf("%d %s", n, outcome)
	}
	// Release before waiting and prevent a second close by the deferred guard.
	release <- struct{}{}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPolicyPrivateLedgerAndSymlinks(t *testing.T) {
	for _, mode := range []string{"directory mode", "file mode", "file symlink", "directory symlink", "empty file", "corrupt file"} {
		t.Run(mode, func(t *testing.T) {
			config, ledger := policyConfig(t)
			dir := filepath.Dir(ledger)
			switch mode {
			case "directory mode":
				os.Chmod(dir, 0755)
				defer os.Chmod(dir, 0700)
			case "file mode":
				os.WriteFile(ledger, []byte("not sqlite"), 0644)
			case "file symlink":
				target := filepath.Join(dir, "target")
				os.WriteFile(target, nil, 0600)
				os.Symlink(target, ledger)
			case "directory symlink":
				target := filepath.Join(dir, "real")
				os.Mkdir(target, 0700)
				link := filepath.Join(dir, "link")
				os.Symlink(target, link)
				data, _ := os.ReadFile(config)
				os.WriteFile(config, []byte(strings.Replace(string(data), ledger, filepath.Join(link, "budget.sqlite"), 1)), 0600)
			case "empty file":
				os.WriteFile(ledger, nil, 0600)
			case "corrupt file":
				os.WriteFile(ledger, []byte("garbage sqlite"), 0600)
			}
			p, err := OpenPolicyFile(config)
			if err == nil {
				p.Close()
				t.Fatal("unsafe ledger accepted")
			}
		})
	}
}

func TestPolicyCredentialDeadlineDurableFailure(t *testing.T) {
	p, _, ledger := openTestPolicy(t)
	c, target := boundedFixture(t, p, func(http.ResponseWriter, *http.Request) { t.Error("sent after credential timeout") }, credentialFunc(func(ctx context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
		<-ctx.Done()
		return azcore.AccessToken{}, ctx.Err()
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(chat("x", false)))
	if _, err := c.Do(req); err == nil {
		t.Fatal("credential timeout ignored")
	}
	n, outcome, in, out, _ := ledgerRows(t, ledger)
	if n != 1 || outcome != "failed" || in.Valid || out.Valid {
		t.Fatalf("%d %s %v %v", n, outcome, in, out)
	}
	if err := boundedSend(c, target, chat("other", false)); err == nil {
		t.Fatal("continued after credential failure")
	}
}
