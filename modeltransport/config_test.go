package modeltransport

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

func TestConfiguredScopeIsNotSwitched(t *testing.T) {
	cred := credentialFunc(func(_ context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
		if len(o.Scopes) != 1 || o.Scopes[0] != "https://cognitiveservices.azure.com/.default" {
			t.Error("configured audience changed")
		}
		return goodCredential()(context.Background(), o)
	})
	_, server := fixture(t, func(http.ResponseWriter, *http.Request) {}, cred)
	cfg := Config{Endpoint: server.URL + "/openai/v1/", Scope: "https://cognitiveservices.azure.com/.default", Deployment: "test-deployment", Credential: cred, Transport: server.Client().Transport.(*http.Transport)}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	cfg.Scope = "https://ai.azure.com/.default"
	if err := request(t, client, context.Background(), server.URL+"/openai/v1/chat/completions"); err != nil {
		t.Fatal(err)
	}
}

func TestDeadlineDuringTokenAcquisitionSendsNothing(t *testing.T) {
	var sends atomic.Int32
	cred := credentialFunc(func(ctx context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
		<-ctx.Done()
		return azcore.AccessToken{}, errors.New(secret)
	})
	client, server := fixture(t, func(http.ResponseWriter, *http.Request) { sends.Add(1) }, cred)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := request(t, client, ctx, server.URL+"/openai/v1/chat/completions")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost deadline: %v", err)
	}
	if sends.Load() != 0 {
		t.Fatal("deadline allowed provider request")
	}
}
