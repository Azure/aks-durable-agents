# Test-environment bootstrap

`bootstrap.py` inventories test-environment dependencies and can manage a fixed
set of persistent Azure prerequisites. The default command is a read-only plan;
`check` is also read-only. Explicit `apply` and `destroy` commands produce dry-run
plans unless execution and an exact reviewed plan are both supplied. No command
writes Entra or GitHub configuration.

This is an operator tool. It uses existing Azure CLI and GitHub CLI sessions.
It never signs in, changes the default subscription, installs CLI extensions,
requests Kubernetes credentials, starts clusters, issues human tokens, calls a
model, enables workflows or dispatches a scenario. Azure writes require an
operator's separate approval of the exact list; generating a plan is not approval.

## Run

Use Python 3.14 and installed `az` and `gh`. Authenticate interactively outside
this tool, using a dedicated Azure CLI profile for the test tenant. Do not point
the tool at the default Azure profile or a production tenant.

Copy [bootstrap.example.json](bootstrap.example.json) to private local storage
and replace its synthetic values. Set `azure.configDir` to an existing absolute
path for that isolated profile. Set the tenant, subscription, repository and
immutable numeric repository/owner IDs explicitly. Resource names describe the
intended dependencies; they do not establish ownership.

```sh
python3 -B ops/aks/bootstrap.py --config "$HOME/.config/aks-test/environment.json"
python3 -B ops/aks/bootstrap.py check --config "$HOME/.config/aks-test/environment.json"
```

Keep configuration and output outside the checkout. Although they must contain
no secrets, resource IDs, endpoints and user object IDs can still be private.
Do not upload the full report as a public workflow artifact or commit a filled
configuration. Unknown configuration fields, duplicate JSON keys, invalid names
and malformed identifiers are rejected. Later versions may add optional fields
with documented defaults; older parsers still reject fields they do not know.
Required breaking changes need a new schema version.

Read permissions are required for the selected subscription's resource metadata,
identity federation, model deployment, budget and role metadata; the selected
tenant's organization, applications, service principals, users, groups and app
assignments; and repository metadata, environments, policies, variables and secret
**names**. No secret value endpoint is used. A permission error is unknown state,
not an empty environment. Read access does not establish write authority.
Environment names are matched case-insensitively. Detailed inventory URL-encodes
names as single path segments, including spaces, slashes and Unicode, up to
GitHub's 255-character limit; unrelated environment names do not change the
expected `nightly-aks` dependency.

## Azure apply and destroy

The optional closed `setup` configuration enables the Azure resource component.
It supplies `modelMode` (`create` or `reference`), the underlying `modelName`
(independent of the deployment name), an explicit provider-registration allowlist,
and a reviewed budget configuration. Existing configurations without `setup`
continue to use the original read-only plan/check behavior.

The budget profile is subscription-wide USD100 Monthly Cost, with actual
50/80/100-percent and forecast100-percent email notifications. Supply its name,
amount, currency, email and active first-of-month start/end dates spanning one
year. USD is an operator assertion when the service cannot yet return currency;
missing currency data is not proof. Dates and recipients are never refreshed on
rerun. Apply requires an active period; an expired period does not prevent exact
owned teardown. Read-only checks can report expiry as a blocker without making
the configuration unreadable. At a month boundary, an approval plan can become
stale; re-plan rather than relaxing the date checks. Budget alerts are delayed and do not stop spend.

The fixed Azure resource set is:

- Only explicitly approved missing registrations among ContainerService, Compute,
  Network, Storage, ManagedIdentity, CognitiveServices and Consumption.
- The budget, nightly cluster/identity resource groups, two user-assigned managed
  identities and the CI GitHub federated credential. Before planning its creation
  and immediately before writing it, the existing `nightly-aks` environment must
  have a verified main-only custom branch policy. A missing, unrestricted or
  unreadable policy blocks federation; the environment subject alone does not
  restrict branches. This tool never creates or repairs that GitHub policy.
- Two narrow custom roles and exactly five scoped grants described in the
  [nightly authorization contract](README.md). Role assignments use `principalId`,
  not the client ID used by consumers. No CI subscription-wide Contributor,
  role-assignment-write or arbitrary node-group-delete authority is added.
- In model-create mode: a dedicated shared-model group, OpenAI S0 account with
  local keys disabled and public network enabled, and the explicit configured
  model/version/SKU/capacity deployment. The profile uses OpenAI format,
  Microsoft.DefaultV2 and OnceNewDefaultVersionAvailable. Reference mode never
  creates or resizes the account/deployment. An owned model-use grant may target
  the explicitly approved referenced account without changing its properties.

There is no cluster/node-group creation, runtime model credential, inference,
Graph writer, GitHub writer, secret/key operation or implicit adoption. Unexpected
federation/grants, incompatible configuration and soft-deleted model-name
collisions block rather than being repaired, purged or restored automatically.

Generate the Azure approval plan with private permissions:

```sh
umask 077
python3 -B ops/aks/bootstrap.py apply \
  --config "$HOME/.config/aks-test/environment.json" > "$HOME/.config/aks-test/apply-plan.json"
```

Review its exact targets, scopes, permissions, configuration/body digests,
blockers and retained resources together with the private configuration. Only
after the operator approves that list:

```sh
python3 -B ops/aks/bootstrap.py apply \
  --config "$HOME/.config/aks-test/environment.json" \
  --execute --plan "$HOME/.config/aks-test/apply-plan.json"
```

The tool recomputes the plan from configuration and fresh cloud state; the file
cannot select arbitrary methods, URLs or bodies. It must be an owner-private
regular file, not a symlink, within the input-size limit. A stale/tampered plan,
failed read or ownership ambiguity stops before writes. The plan gate is explicit
operator input, not a claim that every nested Azure CLI call has its own harness
approval prompt. Do not invoke execution without the separate live-apply go.

Writes are bounded by one overall deadline and a nonblocking local operator lock.
Targets, ownership parents and authorization edges are re-read before changes
and checked afterward. Only related topology affects the state fingerprint;
unrelated subscription activity and spend telemetry do not stale a plan. The
operation reuses unrelated collection observations in memory, never as an ownership
receipt. It makes a full security read before CI federation and a final full read.
Reads may poll asynchronous provisioning, but failed writes are not blindly retried.
After an accepted DELETE, a stale successful state or missing provisioning state
is polled until absence within the same deadline; failed or unknown states stop.
The DELETE request itself is never repeated.
There is no distributed transaction or automatic broad rollback. After an
interruption, rediscover cloud state and review a new remaining-action plan;
never reset credentials or erase unknown resources to make a rerun pass.

`destroy --config ...` also defaults to a dry run and requires its own reviewed
plan plus `--execute`. Default teardown retains the shared model, budget and
identity-group anchor, including an otherwise empty tagged anchor group.
`destroy --include-shared` is a separate destructive plan for owned shared-model
and budget removal. References are never deleted. Unknown children, external
model grants, a live cluster, runtime model federation or managed-node-group
leftovers block. Providers are never unregistered; only empty owned groups can
be removed, and the anchor survives until its dependents are confirmed gone.
Soft deletion is not a purge or a guarantee that a model name can be reused.

Before any nonempty apply/delete plan can execute, the tool reads the repository's
target mapping and scenario flag and checks active/pending runs of the e2e and
cleanup workflows. Missing repository mappings may inherit organization values,
so they are treated as potentially targeted: require an explicit repository-level
scenario `false` unless a different target is established. An enabled/unknown
scenario, active run or unreadable GitHub state blocks. Keep scenario dispatch disabled throughout teardown; leave bootstrap
cleanup enabled while transient cleanup is still needed. Quiescence is rechecked
before the first write, CI federation activation and each group deletion. This is not instant revocation
of previously issued tokens or protection against another administrator racing
the operation. No flags or workflows are changed by this command.

## Read-only results and limits

The original plan/check output is versioned JSON, not an executable apply plan.
With `setup`, it also includes `azureSetup` and `coverage.azureSetup`, exercising
the Azure component's ownership, budget, role and federation checks. Its original
coverage limits below still apply outside that component. Azure dry-run plans
exit `0` when unblocked even if they propose writes, `2` for plan blockers, and
`1` for input/read/execution errors. Invalid CLI flag combinations exit `2`
before remote calls. Successful execution does not imply full readiness. A missing dependency is
an advisory create recommendation, never authorization to create it. Existing
resources can be references without being owned. Plans report safe selected
fields, not raw provider responses, application notes, human tokens or passwords.
Provider errors are captured and replaced with bounded status/reason information.

`ready` is always `false`. A consistent result covers only the checks actually
performed, not environment qualification. In particular, detailed human scopes,
consent and assignments, effective authorization, untaggable-object ownership,
federation trust, budget presence/configuration, complete provider readiness,
custom-role correctness, image signatures, current pricing, budget email delivery
and live human/model/network/replay qualification are not proved by this command. The output identifies
untested coverage rather than inferring it from resource existence.

Exit codes for both commands:

| Code | Meaning |
| --- | --- |
| `0` | The tested dependency scope is consistent; not full readiness |
| `1` | Configuration, identity, inventory or transport could not be validated |
| `2` | The completed inventory has missing, mismatched or blocked dependencies |

Provider registration metadata gates provider-specific inventory calls: a known
unregistered provider gets an advisory registration recommendation, not a failed
list interpreted as absence. Collections unavailable for that reason are listed
in `inventory.unavailableCollections`; their dependencies remain blocked, not
absent. A successfully inventoried missing resource group similarly avoids its
nonexistent child endpoint. Inherited root/management-group role assignments are
retained as reference metadata, never bootstrap-owned.

An enabled environment is not automatically wrong. Observed enable flags are
reported separately from the **proposed** disabled values. Proposed configuration
never inherits an existing scenario/budget approval. Unresolved identity or
release/pricing values must remain unresolved; the tool must not invent client
IDs or copy stale verification dates. Existing nightly jobs continue to consume
their current repository variable names, not environment-only variables or
secrets. No workflow configuration changes are made here.

The supported nightly cluster profile remains the existing lifecycle contract:
westus3, AKS 1.37.0 and two Standard_D2s_v4 nodes, with quota headroom for a surge
node. This tool does not make unsupported region/version/size overrides effective.
Model region is independent of cluster region. See the [AKS workflow contract](README.md)
for the separate manual scenario and independent cleanup.

## Ownership and recovery

Cloud metadata is authoritative. A local receipt, if another operation caches
one, cannot override the tenant and is not required for discovery. Losing a local
cache must not make owned resources undiscoverable.

Direct Azure ownership requires these matching tags:

- `ada-bootstrap-environment`: the configured environment UUID;
- `ada-repository-id`: the configured immutable repository ID;
- `ada-bootstrap-component`: one of `nightly`, `shared-model`, `human-identity`,
  or `persistent-cluster`.

Application ownership uses the corresponding exact string tags:

- `ada-bootstrap-environment:<UUID>`;
- `ada-repository-id:<repository ID>`;
- `ada-bootstrap-component:<component>`.

These markers are separate from the existing nightly purpose/run/expiry tags.
An old nightly tag or a matching display name alone does not establish bootstrap
ownership. Multiple/conflicting markers, duplicate identities and malformed
inventory must not silently choose a target. Discovery scans matching metadata,
not only the configured names, so renaming a resource does not erase ownership.
Markers identify management intent; they do not authorize mutation or protect
against an administrator who can rewrite them.

Service-principal tags can include inherited application tags. Only a verified
relationship to an owned application can establish the corresponding service
principal's ownership. A tagged parent does not automatically own every child.
Federated credentials, budgets, custom roles, assignments and users have no
generic ownership tag field. The Azure setup component uses fixed slots on the
tagged identity resource group for its budget, role and grant IDs and CI-federation
relationship; the owned model account anchors its exact deployment. Slots are
reserved and read back before creating these untaggable objects. Short fixed
values respect Azure's tag limits, and metadata Merge preserves unrelated tags.
A slot alone is insufficient: the live type, fixed GUID, scope, definition and
relationship must also match. Azure ownership's topology stamp excludes human
configuration, budget contact/date fields and local profile paths. An absent reserved object is recoverable creation on apply and
nothing to delete on destroy. Human-user/application-note registries remain
outside this component. Raw notes are never an arbitrary URL source or a
substitute for validating a referenced object.

Existing unmarked resources remain references. Retained grants report the actual
live ID matched by principal, role and scope, not a proposed deterministic ID.
Only newly created resources
receive ownership tags; the tool never adopts old resources, deletes unexpected
children or broadly repairs grants. An ambiguous
create whose ownership marker was never persisted needs explicit operator
recovery. Do not use a broad resource-group deletion to recover it. The nightly
cluster and its temporary model credential remain owned by the existing
lifecycle/cleanup contract, not by this planner.

## Operator checkpoints

The intended end-to-end setup has eight checkpoints. Azure apply/destroy is
limited to the fixed resource component above; the remaining human/repository
and qualification work stays separate. All live writes need exact-list approval.

1. Obtain the fresh tenant, subscription, billing linkage and initial admin
   authority. Choose explicit targets; do not reuse identifiers from an expired
   tenant. A backup administrator or Guest fixture is a separate decision.
2. Sign in interactively to the isolated Azure profile and `gh`. Acquire any
   needed role activation/admin consent. Repository admin is temporary and is
   required for later repository setup, not granted by this tool.
3. Fill the private non-secret configuration. Review model availability, capacity,
   budget currency/recipient, redirect origins, release receipts and dated pricing
   when their setup stages are available. Never put credentials in configuration.
4. Run the planner and review the exact dependency list. Resolve permission and
   capacity blockers without silently changing region, SKU, model or scope.
5. Supply initial user passwords only through a separately approved protected
   interactive path; finish password changes/MFA yourself. Repeated setup must
   never reset an existing password. Missing Guest/group fixtures are untested.
6. Separately approve setup and any persistent-cluster deployment. The planner
   cannot create a disposable nightly cluster or install the application. Keep
   TLS private material in its operator-managed path, never values or summaries.
7. Verify setup before separately approving enablement or a real scenario run.
   Write configuration before enable flags; budget and qualification approvals
   are independent. No bootstrap operation implies inference approval.
8. Choose retention or exact-target teardown and record tenant expiry. Cluster
   stop is not teardown or zero cost; delayed budget alerts do not enforce a
   spending limit.

## Expired-tenant cutover

Before changing the repository's single target configuration, separately approve
disabling scenario/bootstrap flags and quiesce active GitHub runs. For a reachable
old tenant, confirm transient-cluster/federation/node-group cleanup and revoke
old CI federation before switching targets. Preserve the existing cleanup path
while it can still finish a reachable target.

If the old tenant has already expired or cannot be reached, record its cleanup
and revocation as **UNCONFIRMED**. Archive the old target mapping, disable the
flags, and do not block a new-target cutover on proving old absence. An access
failure does not prove deletion, and disabled GitHub flags do not revoke Azure
trust or already issued tokens. Preserve the unresolved security/cost state for
separate operator recovery. Keep flags disabled through mixed configuration and
read back the complete new target before any fresh enablement approval.

No cutover writes are performed by `bootstrap.py`. A new persistent qualification
cluster must remain separate from nightly expiry cleanup. Recreating infrastructure
does not recover retained journals/disks or qualify a new tenant; data migration,
TLS provisioning and application qualification need their own reviewed procedures.
