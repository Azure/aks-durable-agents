package host

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/internal/ownercli"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// Opt-in test-binary fixture only. These issuer endpoints are never compiled
// into cmd/host or cmd/owner-client and must never be used for live approval.
func TestOwnerClientKindServer(t *testing.T) {
	if os.Getenv("ADA_OWNER_KIND_SERVER") != "1" {
		t.Skip("dedicated kind fixture only")
	}
	h := newOwnerHost(t, "127.0.0.1:8443")
	cert, err := os.ReadFile(h.f.config.TLSCert)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/evidence/ca.pem", cert, 0600); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(h.f.config.TLSCert, h.f.config.TLSKey)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	done := make(chan struct{})
	var once sync.Once
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		subject := r.URL.Query().Get("subject")
		if subject != clientOwnerOID && subject != clientOtherOID {
			http.Error(w, "fixture subject refused", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": h.sign(subject)})
	})
	mux.HandleFunc("/inventory", func(w http.ResponseWriter, r *http.Request) {
		p, n := bridgeRuntimeInventory(t, h.data)
		_ = json.NewEncoder(w).Encode(map[string]int{"publications": p, "receipts": n, "model_calls": int(h.f.models.Load())})
	})
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		proof, err := ownerReplayProof(t, h, r.URL.Query().Get("session"))
		if err != nil {
			http.Error(w, "fixture replay failed", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(proof)
	})
	mux.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(done) })
		w.WriteHeader(http.StatusNoContent)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:9444")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go server.Serve(tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}))
	t.Cleanup(func() { _ = server.Close() })
	if err = os.WriteFile("/evidence/ready", []byte("synthetic fixture ready\n"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-t.Context().Done():
		t.Fatal("fixture lifetime expired")
	}
}

type kindOwnerCredential struct {
	client          *http.Client
	issuer, subject string
}

func (c kindOwnerCredential) GetToken(ctx context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.issuer+"/token?subject="+c.subject, nil)
	if err != nil {
		return azcore.AccessToken{}, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return azcore.AccessToken{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return azcore.AccessToken{}, fmt.Errorf("synthetic issuer failed")
	}
	var v struct {
		Token string `json:"token"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&v)
	return azcore.AccessToken{Token: v.Token, ExpiresOn: time.Now().Add(time.Hour)}, err
}

// Runs outside the Pod against TWO --address 127.0.0.1 Pod forwards: the real
// host and a test-only synthetic issuer. Production orchestration/TLS/metadata
// code is unchanged; only credential acquisition is substituted.
func TestOwnerClientKindForward(t *testing.T) {
	target := os.Getenv("ADA_OWNER_KIND_TARGET")
	if target == "" {
		t.Skip("dedicated private Pod forwards required")
	}
	ca := os.Getenv("ADA_OWNER_KIND_CA")
	issuer := os.Getenv("ADA_OWNER_KIND_ISSUER")
	caBytes, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		t.Fatal("invalid fixture CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	factory := func(subject string) ownercli.CredentialFactory {
		return func(context.Context, string, string, string, io.Writer) (azcore.TokenCredential, error) {
			return kindOwnerCredential{httpClient, issuer, subject}, nil
		}
	}
	common := ownerArgs(target, ca)
	owner, other := factory(clientOwnerOID), factory(clientOtherOID)
	uid := ownerStart(t, common, owner)
	// The public inspect response contains the exact tuple reviewed by the user.
	rows, err := runOwner(t, common, owner, "inspect", "--session", uid)
	if err != nil || len(rows) != 1 {
		t.Fatalf("inspect: %v %v", rows, err)
	}
	row := rows[0]
	pending, ok := row["pending"].(map[string]any)
	if !ok {
		t.Fatalf("missing pending request: %v", row)
	}
	action := []string{"--session", uid, "--head", fmt.Sprint(row["head"]), "--execution", fmt.Sprint(pending["executionId"]), "--tool-call", fmt.Sprint(pending["toolCallId"]), "--request-seq", fmt.Sprint(pending["requestSeq"])}
	badName := append([]string(nil), common...)
	badName[5] = "wrong.invalid"
	if _, err = runOwner(t, badName, owner, "inspect", "--session", uid); err == nil {
		t.Fatal("TLS identity mismatch accepted through Pod forward")
	}
	// An unrelated valid certificate is not a trusted host CA.
	wrongCA := filepath.Join(t.TempDir(), "wrong-ca.pem")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(23), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(wrongCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	badCA := append([]string(nil), common...)
	badCA[3] = wrongCA
	if _, err = runOwner(t, badCA, owner, "inspect", "--session", uid); err == nil {
		t.Fatal("untrusted CA accepted")
	}
	if _, err = runOwner(t, common, other, "inspect", "--session", uid); err == nil {
		t.Fatal("foreign owner read accepted")
	}
	otherUID := ownerStart(t, common, other)
	otherRows, err := runOwner(t, common, other, "inspect", "--session", otherUID)
	if err != nil {
		t.Fatal(err)
	}
	op := otherRows[0]["pending"].(map[string]any)
	denied := []string{"--session", otherUID, "--head", fmt.Sprint(otherRows[0]["head"]), "--execution", fmt.Sprint(op["executionId"]), "--tool-call", fmt.Sprint(op["toolCallId"]), "--request-seq", fmt.Sprint(op["requestSeq"])}
	if _, err = runOwner(t, common, other, "approve-run", denied...); err == nil {
		t.Fatal("owner gained approval without independent authorization")
	}
	rows, err = runOwner(t, common, owner, "approve-run", action...)
	if err != nil || len(rows) != 2 || rows[0]["stage"] != "approval" || rows[0]["outcome"] != "approved" || rows[1]["stage"] != "resume" || rows[1]["outcome"] != "resumed" {
		t.Fatalf("explicit separate outcomes: %v %v", rows, err)
	}
	resp, err := httpClient.Get(issuer + "/inventory")
	if err != nil {
		t.Fatal(err)
	}
	var inventory map[string]int
	err = json.NewDecoder(resp.Body).Decode(&inventory)
	_ = resp.Body.Close()
	if err != nil || inventory["publications"] != 1 || inventory["receipts"] != 1 || inventory["model_calls"] != 2 {
		t.Fatalf("publication inventory: %v %v", inventory, err)
	}
	if _, err = runOwner(t, common, owner, "approve-run", action...); err == nil {
		t.Fatal("repeat action accepted")
	}
	resp, err = httpClient.Get(issuer + "/verify?session=" + uid)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	_ = resp.Body.Close()
	var verified struct {
		Completed     bool `json:"completed"`
		ProviderCalls int  `json:"provider_calls"`
		ExecutorCalls int  `json:"executor_calls"`
	}
	if err != nil || resp.StatusCode != 200 || json.Unmarshal(proof, &verified) != nil || !verified.Completed || verified.ProviderCalls != 0 || verified.ExecutorCalls != 0 {
		t.Fatalf("zero-call replay: %s %v", proof, err)
	}
	t.Logf("synthetic kind fixture: literal-loopback Pod forward; verified TLS/name refusal; foreign read and unqualified-owner approval denied; separate approve/resume; one publication; zero-call replay (%s)", strings.TrimSpace(string(proof)))
	resp, err = httpClient.Get(issuer + "/stop")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}
