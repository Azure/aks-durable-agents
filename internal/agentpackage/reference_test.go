package agentpackage

import (
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type offlineTransport struct{ calls atomic.Int64 }

func (t *offlineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return nil, errors.New("unexpected registry access")
}
func TestValidateReferenceIsOfflineAndMatchesPullGuard(t *testing.T) {
	transport := &offlineTransport{}
	p, err := New(Policy{Repositories: []string{"registry.example/suite"}}, transport)
	if err != nil {
		t.Fatal(err)
	}
	valid := "registry.example/suite@sha256:" + strings.Repeat("a", 64)
	if err := p.ValidateReference(valid); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"registry.example/suite:latest", "registry.example/other@sha256:" + strings.Repeat("a", 64), "registry.example/suite@sha256:" + strings.Repeat("A", 64)} {
		err := p.ValidateReference(ref)
		_, pullErr := p.Pull(t.Context(), ref)
		var validation, read *Error
		if !errors.Is(err, ErrUnsupported) || !errors.As(err, &validation) || !errors.As(pullErr, &read) || validation.Rule != read.Rule {
			t.Fatalf("reference policy differs: %v / %v", err, pullErr)
		}
	}
	if transport.calls.Load() != 0 {
		t.Fatal("offline validation used registry transport")
	}
}
