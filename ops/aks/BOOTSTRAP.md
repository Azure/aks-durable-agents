# Read-only test-environment planning

`bootstrap.py` inventories an existing test tenant and subscription and reports
missing or mismatched setup dependencies. It does not create an environment.
The default command is a read-only plan; `check` uses the same observations.
Neither command changes Azure, Entra or GitHub configuration.

This is an operator tool. It uses existing Azure CLI and GitHub CLI sessions.
It never signs in, changes the default subscription, installs CLI extensions,
requests Kubernetes credentials, starts clusters, issues human tokens, calls a
model, enables workflows or dispatches a scenario. There are no `apply` or
`destroy` commands.

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

## Results and limits

Output is versioned JSON, not an executable apply plan. A missing dependency is
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
generic ownership tag field. They remain unowned/reference in this read-only
foundation; exact cloud anchors and supported application-note registries must
be defined and validated with the operations that manage them. Raw notes are
never an arbitrary URL source or a substitute for validating a referenced object.

Existing unmarked resources remain references. This tool does not add tags,
adopt old resources, delete unexpected children or repair grants. An ambiguous
create whose ownership marker was never persisted needs explicit operator
recovery. Do not use a broad resource-group deletion to recover it. The nightly
cluster and its temporary model credential remain owned by the existing
lifecycle/cleanup contract, not by this planner.

## Operator checkpoints

The intended end-to-end setup has eight checkpoints. Only read-only discovery
and advisory planning are available here; create/update/delete operations need
separately implemented tooling and approval of their exact list.

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
