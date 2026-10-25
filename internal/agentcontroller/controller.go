package agentcontroller

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/Azure/aks-durable-agents/internal/agentpackage"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	execution "github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/placement"
	"github.com/agent-primitives/sessions/session"
	"github.com/agent-primitives/sessions/sqlitelog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type Controller struct {
	config   Config
	retained *retained
	registry *session.HarnessRegistry
	cancel   context.CancelFunc
	done     chan struct{}
	once     sync.Once
}

// Start owns the registry, including restored retired placers, before reconciling
// authoritative ownership. No Sessions/admin listener is created here.
func Start(ctx context.Context, c Config, store *sqlitelog.Store, placements *placement.Registry, model execution.ModelFunc, stream execution.StreamFunc) (out *Controller, err error) {
	ctx, cancel := context.WithCancel(ctx)
	ctl := &Controller{config: c, cancel: cancel}
	defer func() {
		if err != nil {
			ctl.Close()
		}
	}()
	if c.Source == nil || c.Namespace == "" || len(c.Binding) == 0 {
		return nil, errors.New("Agent configuration unavailable")
	}
	ctl.retained, err = openRetained(c, model, stream)
	if err != nil {
		return nil, err
	}
	ctl.config.Binding = bytes.Clone(ctl.retained.binding)
	ctl.registry, err = session.NewHarnessRegistry(store, placements, ctl.retained.factory)
	if err != nil {
		return nil, err
	}
	// Missing ownership metadata must not silently turn an ACTIVE row into a static route.
	token := ""
	for {
		page, e := ctl.registry.ListHarnesses(ctx, &v1.ListHarnessesRequest{IncludeRetired: true, PageSize: 500, PageToken: token})
		if e != nil {
			return nil, e
		}
		for _, row := range page.Harnesses {
			if row.Source == v1.HarnessSource_HARNESS_SOURCE_REGISTERED && strings.HasPrefix(row.GetMetadata().GetName(), "a-") {
				if _, ok := ctl.retained.definitions[row.Metadata.Name]; !ok {
					return nil, errors.New("Agent ownership metadata unavailable")
				}
			}
		}
		token = page.NextPageToken
		if token == "" {
			break
		}
	}
	agents, rv, err := c.Source.List(ctx)
	if err != nil {
		return nil, errors.New("Agent startup snapshot unavailable")
	}
	if err = ctl.reconcile(ctx, agents); err != nil {
		return nil, err
	}
	events, err := c.Source.Watch(ctx, rv)
	if err != nil {
		return nil, errors.New("Agent startup watch unavailable")
	}
	ctl.done = make(chan struct{})
	go ctl.run(ctx, events)
	return ctl, nil
}
func (c *Controller) Close() {
	c.once.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		if c.done != nil {
			<-c.done
		}
		if c.registry != nil {
			c.registry.Close()
		}
		if c.retained != nil {
			c.retained.close()
		}
	})
}
func (c *Controller) run(ctx context.Context, events watch.Interface) {
	defer close(c.done)
	for {
		select {
		case <-ctx.Done():
			events.Stop()
			return
		case event, ok := <-events.ResultChan():
			if ok && event.Type == watch.Bookmark {
				continue
			}
		}
		events.Stop()
		for {
			agents, rv, err := c.config.Source.List(ctx)
			if err == nil {
				err = c.reconcile(ctx, agents)
			}
			if err == nil {
				events, err = c.config.Source.Watch(ctx, rv)
			}
			if err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}
func (c *Controller) retire(ctx context.Context, name string) error {
	row, err := c.registry.GetHarness(ctx, &v1.GetHarnessRequest{Name: name})
	if status.Code(err) == codes.NotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if row.State == v1.HarnessState_HARNESS_STATE_RETIRED {
		return nil
	}
	_, err = c.registry.RetireHarness(ctx, &v1.RetireHarnessRequest{Name: name, Reason: "Agent owner no longer admitted"})
	if err != nil {
		row, readErr := c.registry.GetHarness(ctx, &v1.GetHarnessRequest{Name: name})
		if readErr == nil && row.State == v1.HarnessState_HARNESS_STATE_RETIRED {
			return nil
		}
	}
	return err
}
func (c *Controller) reconcile(ctx context.Context, agents []Agent) error {
	current := map[string]Agent{}
	for _, a := range agents {
		if a.Namespace != c.config.Namespace || a.UID == "" || a.Generation < 1 {
			return errors.New("Agent snapshot identity invalid")
		}
		current[string(a.UID)] = a
	}
	for _, d := range c.retained.definitions {
		if d.Namespace != c.config.Namespace {
			return errors.New("Agent state namespace changed")
		}
		a, exists := current[d.UID]
		if !exists || a.DeletionTimestamp != nil || a.Generation != d.Generation || a.Spec != d.Spec || !bytes.Equal(d.Binding, c.config.Binding) {
			if err := c.retire(ctx, d.Harness); err != nil {
				return err
			}
		}
	}
	for _, listed := range agents {
		a, err := c.config.Source.Get(ctx, listed.Name)
		if apierrors.IsNotFound(err) || err == nil && (a.UID != listed.UID || a.DeletionTimestamp != nil) {
			for _, d := range c.retained.definitions {
				if d.UID == string(listed.UID) {
					if e := c.retire(ctx, d.Harness); e != nil {
						return e
					}
				}
			}
			continue
		}
		if err != nil {
			return errors.New("Agent ownership read unavailable")
		}
		if a.Generation != listed.Generation || a.Spec != listed.Spec {
			continue
		}
		if err := c.publish(ctx, a, c.admit(ctx, a)); err != nil {
			return err
		}
	}
	return nil
}
func rejected(a Agent, verified metav1.ConditionStatus, reason string) Status {
	return Status{AgentUID: string(a.UID), ObservedGeneration: a.Generation, Conditions: []metav1.Condition{{Type: "PackageVerified", Status: verified, Reason: reason, ObservedGeneration: a.Generation}, {Type: "Registered", Status: metav1.ConditionFalse, Reason: reason, ObservedGeneration: a.Generation}}}
}
func (c *Controller) admit(ctx context.Context, a Agent) Status {
	st := rejected(a, metav1.ConditionFalse, "UnsupportedBinding")
	if a.Spec.ModelBindingRef.Name != "default" {
		return st
	}
	var d definition
	found := false
	for _, saved := range c.retained.definitions {
		if saved.UID == string(a.UID) {
			d, found = saved, true
			break
		}
	}
	if found {
		if d.Generation != a.Generation || d.Spec != a.Spec {
			return rejected(a, metav1.ConditionFalse, "ImmutableSpecChanged")
		}
	} else {
		if c.config.Puller == nil {
			return rejected(a, metav1.ConditionUnknown, "PackageUnavailable")
		}
		p, err := c.config.Puller.Pull(ctx, a.Spec.Package.Reference)
		if err != nil {
			if errors.Is(err, agentpackage.ErrUnavailable) {
				return rejected(a, metav1.ConditionUnknown, "PackageUnavailable")
			}
			return rejected(a, metav1.ConditionFalse, "PackageRejected")
		}
		st.PackageDigest = p.Digest()
		d, err = c.retained.remember(ctx, a, p)
		if err != nil {
			st.Conditions[0].Status = metav1.ConditionTrue
			st.Conditions[0].Reason = "Verified"
			st.Conditions[1].Reason = "DefinitionRefused"
			return st
		}
	}
	_, dig, _ := strings.Cut(d.Spec.Package.Reference, "@")
	st.PackageDigest = dig
	st.Member = d.Spec.Member
	st.Conditions[0].Status = metav1.ConditionTrue
	st.Conditions[0].Reason = "Verified"
	if !bytes.Equal(d.Binding, c.config.Binding) {
		st.Conditions[1].Reason = "BindingChanged"
		return st
	}
	st.ResolvedBindingDigest = retainedHash(c.retained.binding)
	st.RevisionDigest = d.Revision
	st.HarnessName = d.Harness
	current, ownerErr := c.config.Source.Get(ctx, a.Name)
	if ownerErr != nil || current.UID != a.UID || current.Generation != a.Generation || current.Spec != a.Spec || current.DeletionTimestamp != nil {
		st.Conditions[1].Status = metav1.ConditionUnknown
		st.Conditions[1].Reason = "OwnershipChanged"
		return st
	}
	row, err := c.registry.GetHarness(ctx, &v1.GetHarnessRequest{Name: d.Harness, Observe: true})
	if status.Code(err) == codes.NotFound {
		// Only a confirmed absent durable row permits Register; never replay a RETIRED row.
		_, _ = c.registry.RegisterHarness(ctx, &v1.RegisterHarnessRequest{Name: d.Harness, Spec: c.retained.spec(d)})
		row, err = c.registry.GetHarness(ctx, &v1.GetHarnessRequest{Name: d.Harness, Observe: true})
	}
	if err != nil {
		st.Conditions[1].Status = metav1.ConditionUnknown
		st.Conditions[1].Reason = "RegistrationUncertain"
		return st
	}
	if row.State == v1.HarnessState_HARNESS_STATE_RETIRED {
		st.Conditions[1].Reason = "Retired"
		return st
	}
	if row.State != v1.HarnessState_HARNESS_STATE_ACTIVE || !proto.Equal(row.Spec, c.retained.spec(d)) || row.UnservableReason != "" || row.ObserveError != "" || row.GetObserved().GetId() != d.Harness {
		st.Conditions[1].Reason = "RegistrationUnservable"
		return st
	}
	st.ServedDigest = st.PackageDigest
	st.Conditions[1].Status = metav1.ConditionTrue
	st.Conditions[1].Reason = "Registered"
	return st
}
func (c *Controller) publish(ctx context.Context, a Agent, st Status) error {
	fresh, err := c.config.Source.Get(ctx, a.Name)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if fresh.UID != a.UID || fresh.Generation != a.Generation || fresh.Spec != a.Spec || fresh.DeletionTimestamp != nil {
		return nil
	}
	for i := range st.Conditions {
		condition := &st.Conditions[i]
		condition.Message = condition.Reason
		condition.LastTransitionTime = metav1.Now()
		for _, old := range fresh.Status.Conditions {
			if old.Type == condition.Type && old.Status == condition.Status {
				condition.LastTransitionTime = old.LastTransitionTime
			}
		}
	}
	if reflect.DeepEqual(st, fresh.Status) {
		return nil
	}
	return c.config.Source.UpdateStatus(ctx, fresh, st)
}
