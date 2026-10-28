package agentcontroller

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/Azure/aks-durable-agents/internal/agentpackage"
	"github.com/Azure/aks-durable-agents/internal/qualification"
	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/agent-primitives/sessions/eventlog"
	"github.com/agent-primitives/sessions/sqlitelog"
)

// DurableExecutionConfig is host wiring. Directory must be a NEW run root under
// a private parent, deterministically derived by the factory from the run ID.
// This constructor never adopts execution state, repairs it or deletes it.
type DurableExecutionConfig struct {
	Directory      string
	Pricing        modeltransport.RunPricing
	MaxInputTokens *int
	Credential     azcore.TokenCredential
	Transport      *http.Transport
}

type durableCandidateExecutor struct {
	*CandidateExecutor
	policy    *modeltransport.Policy
	journal   *sqlitelog.Store
	directory string
	once      sync.Once
	closeErr  error
}

// NewDurableCandidateExecutor owns one fresh journal backend and one run ledger.
// It freezes a private manifest before returning an executable handle. The
// factory/parent path are trusted host inputs, not an OS sandbox or attestation.
func NewDurableCandidateExecutor(p *agentpackage.Package, e CandidateExpectations, scope qualification.ExecutionScope, c DurableExecutionConfig) (_ qualification.Executor, err error) {
	refuse := func(cause error) error {
		return fmt.Errorf("%w: durable preparation: %w", ErrCandidateExecution, cause)
	}
	if c.Credential == nil || !filepath.IsAbs(c.Directory) || filepath.Clean(c.Directory) != c.Directory {
		return nil, ErrCandidateExecution
	}
	prepared, err := PrepareCandidate(p, e)
	if err != nil {
		return nil, refuse(err)
	}
	if e.Binding.Scope == "" {
		e.Binding.Scope = modeltransport.DefaultScope
	}
	budget, err := PrepareRunBudget(prepared, e.Binding, qualification.BudgetRequest{RunID: scope.RunID, LedgerPath: filepath.Join(c.Directory, "budget.sqlite"), MaxInputTokens: c.MaxInputTokens, Candidate: modeltransport.RunBinding{ID: "candidate", Endpoint: e.Binding.Endpoint, Scope: e.Binding.Scope, Deployment: e.Binding.Deployment, Pricing: c.Pricing}})
	if err != nil {
		return nil, refuse(err)
	}
	if budget.Config.PlanDigest != scope.PlanDigest {
		return nil, ErrCandidateExecution
	}
	parent := filepath.Dir(c.Directory)
	for cur := parent; ; cur = filepath.Dir(cur) {
		st, e := os.Lstat(cur)
		if e != nil {
			return nil, refuse(e)
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return nil, ErrCandidateExecution
		}
		if cur == parent {
			owner, ok := st.Sys().(*syscall.Stat_t)
			if !ok || owner.Uid != uint32(os.Geteuid()) || st.Mode().Perm() != 0700 {
				return nil, ErrCandidateExecution
			}
		}
		if cur == filepath.Dir(cur) {
			break
		}
	}
	if err = os.Mkdir(c.Directory, 0700); err != nil {
		return nil, refuse(err)
	}
	x := &durableCandidateExecutor{directory: c.Directory}
	defer func() {
		if err != nil {
			err = errors.Join(err, x.Close())
		}
	}()
	root, err := os.OpenRoot(c.Directory)
	if err != nil {
		return nil, refuse(err)
	}
	defer root.Close()
	create := func(name string, data []byte) error {
		f, e := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(data)
		if e == nil {
			e = f.Sync()
		}
		return errors.Join(e, f.Close())
	}
	x.policy, err = modeltransport.OpenRunPolicy(budget.Config)
	if err != nil {
		return nil, refuse(err)
	}
	if err = create("sessions.sqlite", nil); err != nil {
		return nil, refuse(err)
	}
	uri := url.URL{Scheme: "file", Path: filepath.Join(c.Directory, "sessions.sqlite")}
	x.journal, err = sqlitelog.Open(uri.String())
	if err != nil {
		return nil, refuse(err)
	}
	x.CandidateExecutor, err = NewCandidateExecutor(p, e, ExecutionConfig{RunID: scope.RunID, Policy: x.policy, Credential: c.Credential, Transport: c.Transport, Journal: func(uid string) (eventlog.Store, error) { return x.journal.Session(uid), nil }})
	if err != nil {
		return nil, refuse(err)
	}
	manifest, err := json.Marshal(struct {
		Version  int
		Scope    qualification.ExecutionScope
		Info     qualification.ExecutionInfo
		Snapshot json.RawMessage
	}{1, scope, x.Info(), x.policy.Snapshot()})
	if err != nil {
		return nil, refuse(err)
	}
	if err = create("scope.json", manifest); err != nil {
		return nil, refuse(err)
	}
	if err = syncExecutionDirectory(c.Directory); err != nil {
		return nil, refuse(err)
	}
	if err = syncExecutionDirectory(parent); err != nil {
		return nil, refuse(err)
	}
	return x, nil
}

func syncExecutionDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func (x *durableCandidateExecutor) Close() error {
	x.once.Do(func() {
		if x.CandidateExecutor != nil {
			x.closeErr = errors.Join(x.closeErr, x.CandidateExecutor.Close())
		}
		if x.policy != nil {
			x.closeErr = errors.Join(x.closeErr, x.policy.Close())
		}
		if x.journal != nil {
			x.closeErr = errors.Join(x.closeErr, x.journal.Close())
		}
		x.closeErr = errors.Join(x.closeErr, syncExecutionDirectory(x.directory))
	})
	return x.closeErr
}

var _ qualification.Executor = (*durableCandidateExecutor)(nil)
