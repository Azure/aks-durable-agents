package ownercli

import (
	"context"
	"errors"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

type deviceLogin interface {
	azcore.TokenCredential
	Authenticate(context.Context, *policy.TokenRequestOptions) (azidentity.AuthenticationRecord, error)
}

// DeviceCredential signs in once with an explicit tenant, public client and delegated scope.
// Default cache is memory-only; GetToken cannot start another interactive authentication.
func DeviceCredential(ctx context.Context, tenant, clientID, scope string, prompt io.Writer) (azcore.TokenCredential, error) {
	return deviceCredential(ctx, tenant, clientID, scope, prompt, func(o *azidentity.DeviceCodeCredentialOptions) (deviceLogin, error) {
		return azidentity.NewDeviceCodeCredential(o)
	})
}
func deviceCredential(ctx context.Context, tenant, clientID, scope string, prompt io.Writer, newCredential func(*azidentity.DeviceCodeCredentialOptions) (deviceLogin, error)) (azcore.TokenCredential, error) {
	if !validGUID(tenant) || !validGUID(clientID) || !validScope(scope) || prompt == nil {
		return nil, errors.New("explicit delegated sign-in settings and private prompt writer required")
	}
	c, err := newCredential(&azidentity.DeviceCodeCredentialOptions{
		TenantID: tenant, ClientID: clientID, DisableAutomaticAuthentication: true,
		UserPrompt: func(_ context.Context, m azidentity.DeviceCodeMessage) error {
			message := []byte(m.Message + "\n")
			if n, err := prompt.Write(message); err != nil || n != len(message) {
				return errors.New("private sign-in prompt output failed")
			}
			return nil
		},
	})
	if err != nil || c == nil {
		return nil, errors.New("delegated credential initialization failed")
	}
	if _, err := c.Authenticate(ctx, &policy.TokenRequestOptions{Scopes: []string{scope}}); err != nil {
		return nil, errors.New("delegated sign-in failed")
	}
	return c, nil
}
