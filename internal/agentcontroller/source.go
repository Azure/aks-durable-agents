package agentcontroller

import (
	"context"

	"k8s.io/apimachinery/pkg/watch"
)

// Source reads a complete namespace snapshot and publishes controller-owned status.
type Source interface {
	List(context.Context) ([]Agent, string, error)
	Get(context.Context, string) (Agent, error)
	UpdateStatus(context.Context, Agent, Status) error
	Watch(context.Context, string) (watch.Interface, error)
}
