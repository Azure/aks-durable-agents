package agentcontroller

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

var agentResource = schema.GroupVersionResource{Group: "agents.aks-durable-agents.io", Version: "v1alpha1", Resource: "agents"}

type clientSource struct{ agents dynamic.ResourceInterface }

// Kubernetes uses the official in-cluster credentials when config is nil.
func Kubernetes(namespace string, config *rest.Config) (Source, error) {
	if namespace == "" {
		return nil, fmt.Errorf("Agent namespace is required")
	}
	var err error
	if config == nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}
	config = rest.CopyConfig(config)
	config.Timeout = 10 * time.Second
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &clientSource{agents: client.Resource(agentResource).Namespace(namespace)}, nil
}

func decodeAgent(object *unstructured.Unstructured) (Agent, error) {
	var a Agent
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &a)
	return a, err
}

func (s *clientSource) List(ctx context.Context) ([]Agent, string, error) {
	var agents []Agent
	var rv string
	options := metav1.ListOptions{Limit: 500}
	for {
		page, err := s.agents.List(ctx, options)
		if err != nil {
			return nil, "", err
		}
		if rv == "" {
			rv = page.GetResourceVersion()
		}
		for i := range page.Items {
			a, err := decodeAgent(&page.Items[i])
			if err != nil {
				return nil, "", err
			}
			agents = append(agents, a)
		}
		options.Continue = page.GetContinue()
		if options.Continue == "" {
			return agents, rv, nil
		}
	}
}

func (s *clientSource) Get(ctx context.Context, name string) (Agent, error) {
	object, err := s.agents.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return Agent{}, err
	}
	return decodeAgent(object)
}

func (s *clientSource) UpdateStatus(ctx context.Context, expected Agent, status Status) error {
	object, err := s.agents.Get(ctx, expected.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	fresh, err := decodeAgent(object)
	if err != nil {
		return err
	}
	if fresh.UID != expected.UID || fresh.Generation != expected.Generation || fresh.Spec != expected.Spec || fresh.DeletionTimestamp != nil {
		return apierrors.NewConflict(agentResource.GroupResource(), expected.Name, fmt.Errorf("Agent identity or spec changed"))
	}
	value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&status)
	if err != nil {
		return err
	}
	// Full status PUT removes absent optional fields. Fresh UID/resourceVersion
	// make delete/recreate and intervening changes conflict at the API server.
	object.Object["status"] = value
	_, err = s.agents.UpdateStatus(ctx, object, metav1.UpdateOptions{})
	return err
}

func (s *clientSource) Watch(ctx context.Context, rv string) (watch.Interface, error) {
	timeout := int64(10)
	return s.agents.Watch(ctx, metav1.ListOptions{ResourceVersion: rv, TimeoutSeconds: &timeout})
}
