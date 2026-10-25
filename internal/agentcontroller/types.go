// Package agentcontroller provides immutable Agent types and a retained host runtime.
package agentcontroller

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Agent is the namespaced agents.aks-durable-agents.io/v1alpha1 resource.
type Agent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              Spec   `json:"spec"`
	Status            Status `json:"status,omitempty"`
}

type Spec struct {
	Package         PackageReference `json:"package"`
	Member          string           `json:"member"`
	ModelBindingRef BindingReference `json:"modelBindingRef"`
}

type PackageReference struct {
	Reference string `json:"reference"`
}

type BindingReference struct {
	Name string `json:"name"`
}

// Status records last-observed admission, not host or inference availability.
type Status struct {
	AgentUID              string             `json:"agentUID,omitempty"`
	ObservedGeneration    int64              `json:"observedGeneration,omitempty"`
	PackageDigest         string             `json:"packageDigest,omitempty"`
	Member                string             `json:"member,omitempty"`
	ResolvedBindingDigest string             `json:"resolvedBindingDigest,omitempty"`
	RevisionDigest        string             `json:"revisionDigest,omitempty"`
	HarnessName           string             `json:"harnessName,omitempty"`
	ServedDigest          string             `json:"servedDigest,omitempty"`
	Conditions            []metav1.Condition `json:"conditions,omitempty"`
}
