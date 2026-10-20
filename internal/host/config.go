// Package host assembles the private-proof sessions host from public packages.
package host

import (
	"errors"
	"github.com/Azure/aks-durable-agents/entraauth"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/authn"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// Config is immutable operator configuration. Required is admission-only until
// upstream sessions supplies resource enforcement and durable policy activation.
type Config struct {
	Addr, HealthAddr, Journal string
	Mode                      authn.Mode
	TLSCert, TLSKey           string
	Identity                  entraauth.Config
	Approvers                 []api.CallerIdentity
	Harnesses                 map[string]string
	Substrate                 *SubstrateConfig
	ToolExecutors             string
	// HarnessService is an explicit exact in-cluster Service FQDN:port exception.
	// It does not relax the loopback Sessions or health listeners.
	HarnessService string
	// HarnessServices adds exact exceptions; HarnessService remains the first/legacy entry.
	HarnessServices                       []string
	PeerNodeFile, NodeName                string
	ModelPolicy                           string
	ModelEndpoint, Deployment, ModelScope string
	// ModelTransport and ModelCredential are trusted in-process host settings,
	// never CLI, environment, or auth-config input. Nil credential preserves
	// the production workload-identity-only behavior.
	ModelTransport  *http.Transport
	ModelCredential azcore.TokenCredential `json:"-"`
}

func (c Config) validate() error {
	if c.Mode != authn.Off && c.Mode != authn.Required {
		return errors.New("auth mode must be off or required")
	}
	if !loopback(c.Addr) || !loopback(c.HealthAddr) {
		return errors.New("sessions and health listeners must use literal loopback addresses until sessions c1/c2")
	}
	_, port, _ := net.SplitHostPort(c.Addr)
	_, healthPort, _ := net.SplitHostPort(c.HealthAddr)
	if port != "0" && port == healthPort {
		return errors.New("sessions and health must use different ports")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") || (c.Mode == authn.Required && c.TLSCert == "") {
		return errors.New("required mode needs a TLS certificate and key")
	}
	if c.Journal == "" || (len(c.Harnesses) == 0 && c.Substrate == nil) {
		return errors.New("journal and at least one harness are required")
	}
	if c.Substrate != nil {
		if len(c.Harnesses) != 0 || c.HarnessService != "" || len(c.HarnessServices) != 0 || c.PeerNodeFile != "" || c.NodeName != "" {
			return errors.New("substrate cannot be combined with remote harnesses or fixture co-location settings")
		}
		if err := c.Substrate.validate(); err != nil {
			return err
		}
	}
	services := make(map[string]bool)
	for i, service := range append([]string{c.HarnessService}, c.HarnessServices...) {
		if i == 0 && service == "" {
			continue
		}
		if !inClusterService(service) || services[service] {
			return errors.New("harness-service requires unique exact service.namespace.svc.cluster.local:port values")
		}
		services[service] = true
	}
	for name, addr := range c.Harnesses {
		if strings.HasPrefix(name, "bundle-v4-") && !nativeHarnessName.MatchString(name) {
			return errors.New("native harness name requires an exact lowercase bundle-v4 digest")
		}
		if name == "" || (!loopback(addr) && !services[addr]) {
			return errors.New("harness address must be loopback or match the explicitly configured in-cluster Service")
		}
	}
	if err := c.checkPlacement(); err != nil {
		return err
	}
	for _, caller := range c.Approvers {
		if !caller.Valid() {
			return errors.New("approvers require exact issuer and subject")
		}
		// An approver the verifier can never emit would deny every approval silently.
		if c.Mode == authn.Required && !c.Identity.ValidIdentity(caller) {
			return errors.New("approvers must use the identity issuer and a subject in the form subjectClaim requires (lowercase GUID for oid)")
		}
	}
	return nil
}

func loopback(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	return ip != nil && ip.IsLoopback() && err == nil && n >= 0 && n <= 65535
}
