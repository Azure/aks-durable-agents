package agentcontroller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
)

const agentPath = "/apis/agents.aks-durable-agents.io/v1alpha1/namespaces/team/agents"

func kubeAgent() Agent {
	return Agent{TypeMeta: metav1.TypeMeta{APIVersion: "agents.aks-durable-agents.io/v1alpha1", Kind: "Agent"},
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "team", UID: types.UID("uid-1"), Generation: 1, ResourceVersion: "10"},
		Spec:       Spec{Package: PackageReference{Reference: "registry.example/team/agent@sha256:" + strings.Repeat("a", 64)}, Member: "helper", ModelBindingRef: BindingReference{Name: "default"}}}
}

func kubeSource(t *testing.T, handler http.HandlerFunc) Source {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	source, err := Kubernetes("team", &rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func sendJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Error(err)
	}
}

func TestKubernetesTypesJSONContract(t *testing.T) {
	a := kubeAgent()
	a.Status = Status{AgentUID: "uid-1", ObservedGeneration: 1, PackageDigest: "sha256:a", Member: "helper", ResolvedBindingDigest: "sha256:b", RevisionDigest: "sha256:c", HarnessName: "runner", Conditions: []metav1.Condition{{Type: "PackageVerified"}}}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	wantSpec := map[string]any{"package": map[string]any{"reference": a.Spec.Package.Reference}, "member": "helper", "modelBindingRef": map[string]any{"name": "default"}}
	if !reflect.DeepEqual(object["spec"], wantSpec) || object["kind"] != "Agent" || object["metadata"].(map[string]any)["uid"] != "uid-1" {
		t.Fatalf("wrong API shape: %s", data)
	}
	status := object["status"].(map[string]any)
	if _, present := status["servedDigest"]; present || len(status) != 8 {
		t.Fatalf("optional fields not omitted: %s", data)
	}
}

func TestKubernetesListCompleteSnapshotAndGet(t *testing.T) {
	calls := 0
	source := kubeSource(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method: %s", r.Method)
		}
		if r.URL.Path == agentPath+"/example" {
			sendJSON(t, w, kubeAgent())
			return
		}
		if r.URL.Path != agentPath || r.URL.Query().Get("limit") != "500" {
			t.Errorf("list URL: %s", r.URL)
		}
		calls++
		meta := map[string]any{"resourceVersion": "20"}
		if calls == 1 {
			meta["continue"] = "next-page"
		} else if r.URL.Query().Get("continue") != "next-page" {
			t.Error("missing continuation token")
		}
		a := kubeAgent()
		a.Name = fmt.Sprintf("agent-%d", calls)
		sendJSON(t, w, map[string]any{"apiVersion": a.APIVersion, "kind": "AgentList", "metadata": meta, "items": []Agent{a}})
	})
	items, rv, err := source.List(context.Background())
	if err != nil || len(items) != 2 || rv != "20" || items[1].Name != "agent-2" {
		t.Fatalf("snapshot: %+v %q %v", items, rv, err)
	}
	got, err := source.Get(context.Background(), "example")
	if err != nil || got.UID != "uid-1" || got.Spec != kubeAgent().Spec {
		t.Fatalf("get: %+v %v", got, err)
	}
}

func TestKubernetesListFailureNeverReturnsPartialSnapshot(t *testing.T) {
	for _, failure := range []string{"expired", "invalid-object"} {
		t.Run(failure, func(t *testing.T) {
			source := kubeSource(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("continue") == "" {
					sendJSON(t, w, map[string]any{"apiVersion": kubeAgent().APIVersion, "kind": "AgentList", "metadata": map[string]any{"resourceVersion": "20", "continue": "next"}, "items": []Agent{kubeAgent()}})
				} else if failure == "expired" {
					w.WriteHeader(http.StatusGone)
					_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Expired","code":410}`))
				} else {
					sendJSON(t, w, map[string]any{"apiVersion": kubeAgent().APIVersion, "kind": "AgentList", "metadata": map[string]any{"resourceVersion": "20"}, "items": []any{map[string]any{"spec": "bad"}}})
				}
			})
			items, rv, err := source.List(context.Background())
			if err == nil || items != nil || rv != "" {
				t.Fatalf("failure returned authoritative data: %+v %q %v", items, rv, err)
			}
			if failure == "expired" && !apierrors.IsResourceExpired(err) && !apierrors.IsGone(err) {
				t.Fatalf("lost API status: %v", err)
			}
		})
	}
}

func TestKubernetesStatusPUTUsesFreshVersionAndClearsServedDigest(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(fmt.Sprint(conflict), func(t *testing.T) {
			puts := 0
			source := kubeSource(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" && r.URL.Path == agentPath+"/example" {
					fresh := kubeAgent()
					fresh.ResourceVersion = "15"
					fresh.Status.ServedDigest = "sha256:old"
					sendJSON(t, w, fresh)
					return
				}
				puts++
				if r.Method != "PUT" || r.URL.Path != agentPath+"/example/status" {
					t.Errorf("status must be full PUT: %s %s", r.Method, r.URL)
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				meta := body["metadata"].(map[string]any)
				status := body["status"].(map[string]any)
				if meta["resourceVersion"] != "15" || meta["uid"] != "uid-1" || status["agentUID"] != "uid-1" {
					t.Errorf("missing fresh UID/RV precondition: %+v", body)
				}
				if _, exists := status["servedDigest"]; exists {
					t.Error("servedDigest must be removed")
				}
				if conflict {
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Conflict","code":409}`))
				} else {
					sendJSON(t, w, body)
				}
			})
			err := source.UpdateStatus(context.Background(), kubeAgent(), Status{AgentUID: "uid-1", ObservedGeneration: 1})
			if puts != 1 || (conflict && !apierrors.IsConflict(err)) || (!conflict && err != nil) {
				t.Fatalf("status writes=%d err=%v", puts, err)
			}
		})
	}
}

func TestKubernetesStatusRejectsChangedOwnerOrSpec(t *testing.T) {
	for _, change := range []string{"uid", "generation", "spec", "deleting"} {
		t.Run(change, func(t *testing.T) {
			source := kubeSource(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Error("stale owner must not publish status")
				}
				fresh := kubeAgent()
				switch change {
				case "uid":
					fresh.UID = "uid-new"
				case "generation":
					fresh.Generation++
				case "spec":
					fresh.Spec.Member = "other"
				case "deleting":
					now := metav1.Now()
					fresh.DeletionTimestamp = &now
				}
				sendJSON(t, w, fresh)
			})
			if err := source.UpdateStatus(context.Background(), kubeAgent(), Status{}); err == nil {
				t.Fatal("changed identity accepted")
			}
		})
	}
}

func TestKubernetesWatchSnapshotVersionErrorAndClose(t *testing.T) {
	source := kubeSource(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != agentPath || r.URL.Query().Get("watch") != "true" || r.URL.Query().Get("resourceVersion") != "20" || r.URL.Query().Get("timeoutSeconds") != "10" {
			t.Errorf("watch URL: %s", r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"ADDED","object":{"apiVersion":"agents.aks-durable-agents.io/v1alpha1","kind":"Agent","metadata":{"name":"example"}}}` + "\n"))
		_, _ = w.Write([]byte(`{"type":"ERROR","object":{"apiVersion":"v1","kind":"Status","reason":"Expired","code":410}}` + "\n"))
	})
	stream, err := source.Watch(context.Background(), "20")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Stop()
	if event := <-stream.ResultChan(); event.Type != watch.Added {
		t.Fatalf("first event: %+v", event)
	}
	if event := <-stream.ResultChan(); event.Type != watch.Error || !apierrors.IsResourceExpired(apierrors.FromObject(event.Object)) {
		t.Fatalf("expired event: %+v", event)
	}
	select {
	case _, open := <-stream.ResultChan():
		if open {
			t.Fatal("watch should end at EOF")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watch did not close")
	}
}

func TestKubernetesWatchContextCancellation(t *testing.T) {
	source := kubeSource(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := source.Watch(ctx, "20")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Stop()
	cancel()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case event, open := <-stream.ResultChan():
			if !open {
				return
			}
			if event.Type != watch.Error {
				t.Fatalf("unexpected event: %+v", event)
			}
		case <-deadline:
			t.Fatal("watch ignored context cancellation")
		}
	}
}

func TestKubernetesReadRequestsBoundedWithoutMutatingConfig(t *testing.T) {
	for _, operation := range []string{"list", "get", "status"} {
		t.Run(operation, func(t *testing.T) {
			calls := 0
			config := &rest.Config{Host: "https://api.example", Timeout: time.Hour,
				Transport: requestTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					deadline, ok := r.Context().Deadline()
					remaining := time.Until(deadline)
					if !ok || remaining <= 0 || remaining > 10*time.Second {
						t.Errorf("unbounded API read: deadline=%v remaining=%v", ok, remaining)
					}
					return nil, errors.New("deliberate transport failure")
				})}
			source, err := Kubernetes("team", config)
			if err != nil {
				t.Fatal(err)
			}
			if config.Timeout != time.Hour {
				t.Fatal("constructor mutated caller's config")
			}
			switch operation {
			case "list":
				_, _, err = source.List(context.Background())
			case "get":
				_, err = source.Get(context.Background(), "example")
			case "status":
				err = source.UpdateStatus(context.Background(), kubeAgent(), Status{})
			}
			if err == nil || calls != 1 {
				t.Fatalf("transport calls=%d err=%v", calls, err)
			}
		})
	}
}

type requestTransport func(*http.Request) (*http.Response, error)

func (f requestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestKubernetesReadsHonorParentCancellation(t *testing.T) {
	for _, operation := range []string{"list", "get", "status"} {
		t.Run(operation, func(t *testing.T) {
			started := make(chan struct{})
			source := kubeSource(t, func(w http.ResponseWriter, r *http.Request) {
				close(started)
				<-r.Context().Done()
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				var err error
				switch operation {
				case "list":
					_, _, err = source.List(ctx)
				case "get":
					_, err = source.Get(ctx, "example")
				case "status":
					err = source.UpdateStatus(ctx, kubeAgent(), Status{})
				}
				result <- err
			}()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("API request not started")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("lost cancellation: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("API read ignored parent cancellation")
			}
		})
	}
}

func TestKubernetesRejectsInvalidResourceNamesBeforeHTTP(t *testing.T) {
	source := kubeSource(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("invalid name escaped client validation: %s", r.URL)
		http.Error(w, "unexpected request", http.StatusBadRequest)
	})
	for _, name := range []string{"../example", "example/status", "."} {
		if _, err := source.Get(context.Background(), name); err == nil {
			t.Fatalf("invalid Get name accepted: %q", name)
		}
		a := kubeAgent()
		a.Name = name
		if err := source.UpdateStatus(context.Background(), a, Status{}); err == nil {
			t.Fatalf("invalid status name accepted: %q", name)
		}
	}
}

func TestKubernetesWithoutConfigUsesInClusterConfiguration(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := Kubernetes("team", nil); err == nil {
		t.Fatal("expected official InClusterConfig error outside cluster")
	}
}
