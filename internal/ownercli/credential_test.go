package ownercli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

type login struct {
	auths, tokens int
	scope         []string
	err           error
}

func (l *login) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	l.tokens++
	return azcore.AccessToken{}, errors.New("must not obtain token during Authenticate")
}
func (l *login) Authenticate(_ context.Context, o *policy.TokenRequestOptions) (azidentity.AuthenticationRecord, error) {
	l.auths++
	l.scope = o.Scopes
	return azidentity.AuthenticationRecord{}, l.err
}
func TestDeviceLoginExplicitOptionsAndPrivatePrompt(t *testing.T) {
	var prompt bytes.Buffer
	l := &login{}
	c, err := deviceCredential(context.Background(), tenant, clientID, scope, &prompt, func(o *azidentity.DeviceCodeCredentialOptions) (deviceLogin, error) {
		if o.TenantID != tenant || o.ClientID != clientID || !o.DisableAutomaticAuthentication || !reflect.ValueOf(o.Cache).IsZero() || len(o.AdditionallyAllowedTenants) != 0 || o.UserPrompt == nil {
			t.Fatalf("unsafe device options: %+v", o)
		}
		if err := o.UserPrompt(context.Background(), azidentity.DeviceCodeMessage{Message: "private sign-in instructions"}); err != nil {
			t.Fatal(err)
		}
		return l, nil
	})
	if err != nil || c != l || l.auths != 1 || l.tokens != 0 || len(l.scope) != 1 || l.scope[0] != scope || prompt.String() != "private sign-in instructions\n" {
		t.Fatalf("login=%+v prompt=%s err=%v", l, &prompt, err)
	}
}
func TestDeviceLoginFailureHasNoFallbackOrRawError(t *testing.T) {
	for _, mode := range []string{"constructor", "authenticate", "prompt", "nil-prompt", "invalid-options"} {
		t.Run(mode, func(t *testing.T) {
			l := &login{}
			constructs := 0
			var prompt io.Writer = io.Discard
			ten := tenant
			if mode == "nil-prompt" {
				prompt = nil
			}
			if mode == "invalid-options" {
				ten = "common"
			}
			if mode == "prompt" {
				prompt = &failWriter{}
			}
			if mode == "authenticate" {
				l.err = errors.New(secret)
			}
			c, err := deviceCredential(context.Background(), ten, clientID, scope, prompt, func(o *azidentity.DeviceCodeCredentialOptions) (deviceLogin, error) {
				constructs++
				if mode == "constructor" {
					return nil, errors.New(secret)
				}
				if mode == "prompt" {
					if err := o.UserPrompt(context.Background(), azidentity.DeviceCodeMessage{Message: "instructions"}); err != nil {
						return nil, err
					}
				}
				return l, nil
			})
			if err == nil || c != nil || strings.Contains(err.Error(), secret) || constructs > 1 || l.auths > 1 {
				t.Fatalf("unsafe failure c=%v err=%v construct=%d auth=%d", c, err, constructs, l.auths)
			}
			if (mode == "invalid-options" || mode == "nil-prompt") && constructs != 0 {
				t.Fatal("constructor called before validation")
			}
		})
	}
}
func TestShortDevicePromptStopsAuthentication(t *testing.T) {
	l := &login{}
	_, err := deviceCredential(t.Context(), tenant, clientID, scope, shortWriter{}, func(o *azidentity.DeviceCodeCredentialOptions) (deviceLogin, error) {
		if err := o.UserPrompt(t.Context(), azidentity.DeviceCodeMessage{Message: "private sign-in instructions"}); err != nil {
			return nil, err
		}
		return l, nil
	})
	if err == nil || l.auths != 0 {
		t.Fatalf("login after incomplete prompt: %v", err)
	}
}

func TestBearerRequiresSecureTransportAndExactScope(t *testing.T) {
	cred, _ := goodFactory(context.Background(), tenant, clientID, scope, io.Discard)
	b := bearer{credential: cred, scope: scope}
	if !b.RequireTransportSecurity() {
		t.Fatal("allows plaintext")
	}
	if _, err := b.GetRequestMetadata(context.Background()); err == nil {
		t.Fatal("metadata available without verified TLS")
	}
	if _, err := b.token(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := cred.(*tokenCredential)
	if len(c.scopes) != 1 || c.scopes[0] != scope {
		t.Fatalf("scopes=%v", c.scopes)
	}
}
