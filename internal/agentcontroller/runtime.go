package agentcontroller

import "github.com/Azure/aks-durable-agents/internal/agentpackage"

// Config supplies host-owned settings, not fields accepted from an Agent resource.
// Binding is a canonicalizable non-secret snapshot; callbacks must enforce it.
type Config struct {
	Namespace, Directory, Model string
	Binding                     []byte
	Puller                      *agentpackage.Puller
	Source                      Source
}
