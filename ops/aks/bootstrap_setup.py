"""Approval-bound persistent Azure setup. No Graph or GitHub mutations."""
import datetime
import fcntl
import json
import os
import re
import stat
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlencode

from bootstrap_inventory import (
    ARM,
    GUID,
    InventoryError,
    ReadOnly,
    environment_segment,
    ownership,
    unique_object,
    valid_guid,
)
from bootstrap_resources import (
    CONFIG_TAG,
    DEPLOYMENT_TAG,
    PROVIDERS,
    SLOT_PREFIX,
    digest,
    find,
    identifier,
    markers,
    matching,
    resolved_body,
    resource_specs,
    root,
    slot,
    subset,
    topology_digest,
)


class SetupError(InventoryError):
    """Only fixed, non-sensitive messages cross the CLI boundary."""


def require(condition, reason='setup: invalid configuration'):
    if not condition:
        raise SetupError(reason)


def setup_configuration(config):
    s = config.get('setup')
    require(isinstance(s, dict) and set(s) == {'modelMode', 'modelName', 'registerProviders', 'budget'})
    require(s['modelMode'] in ('create', 'reference'))
    require(isinstance(s['modelName'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', s['modelName']))
    providers = s['registerProviders']
    require(isinstance(providers, list) and all(isinstance(p, str) and p in PROVIDERS for p in providers))
    require(len(providers) == len(set(providers)))
    b = s['budget']
    require(isinstance(b, dict) and set(b) == {'name', 'amount', 'currency', 'email', 'startDate', 'endDate'})
    require(type(b['amount']) is int and b['amount'] == 100 and b['currency'] == 'USD')
    require(isinstance(b['name'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,62}', b['name']))
    require(isinstance(b['email'], str) and len(b['email']) <= 254
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]*@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}', b['email'])
            and '..' not in b['email'])
    try:
        start, end = (datetime.date.fromisoformat(b[k]) for k in ('startDate', 'endDate'))
        require(start.isoformat() == b['startDate'] and end.isoformat() == b['endDate'])
        require(start.day == end.day == 1 and end == start.replace(year=start.year + 1))
    except (ValueError, TypeError):
        raise SetupError('setup: invalid budget dates') from None
    return s


def setup_routes(config):
    base = ARM + root(config)
    n, m = config['nightly'], config['model']
    anchor = base + '/resourceGroups/' + n['identityResourceGroup']
    account = base + '/resourceGroups/' + m['resourceGroup'] + '/providers/Microsoft.CognitiveServices/accounts/' + m['accountName']
    paths = {
        'groups': (base + '/resourcegroups', '2021-04-01'),
        'resources': (base + '/resources', '2021-04-01'),
        'providers': (base + '/providers', '2021-04-01'),
        'roles': (base + '/providers/Microsoft.Authorization/roleDefinitions', '2022-04-01'),
        'rgRoles': (anchor + '/providers/Microsoft.Authorization/roleDefinitions', '2022-04-01'),
        'assignments': (base + '/providers/Microsoft.Authorization/roleAssignments', '2022-04-01'),
        'accountAssignments': (account + '/providers/Microsoft.Authorization/roleAssignments', '2022-04-01'),
        'identities': (anchor + '/providers/Microsoft.ManagedIdentity/userAssignedIdentities', '2023-01-31'),
        'accounts': (base + '/providers/Microsoft.CognitiveServices/accounts', '2024-10-01'),
        'deletedAccounts': (base + '/providers/Microsoft.CognitiveServices/deletedAccounts', '2024-10-01'),
        'deployments': (account + '/deployments', '2024-10-01'),
        'budgets': (base + '/providers/Microsoft.Consumption/budgets', '2024-08-01')}
    for key, name in [('ciFics', n['ciIdentityName']), ('modelFics', n['modelIdentityName'])]:
        paths[key] = (anchor + '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/' + name + '/federatedIdentityCredentials', '2023-01-31')
    result = {k: path + '?api-version=' + version for k, (path, version) in paths.items()}
    result['rgRoles'] += '&' + urlencode({'$filter': "type eq 'CustomRole'"})
    return result


class SetupReader(ReadOnly):
    def __init__(self, config, deadline=None):
        super().__init__(config)
        self.arm_routes.update(setup_routes(config).values())
        self.deadline = deadline or time.monotonic() + 600
        self.collections = {}

    def _run(self, args):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'setup: deadline exceeded')
        environment = dict(os.environ, AZURE_CONFIG_DIR=self.config['azure']['configDir'],
                           AZURE_EXTENSION_USE_DYNAMIC_INSTALL='no', AZURE_CORE_COLLECT_TELEMETRY='no', GH_HOST='github.com')
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=min(30, remaining),
                                    check=False, env=environment)
        except (OSError, subprocess.TimeoutExpired):
            raise SetupError('setup: read unavailable or timed out') from None
        require(result.returncode == 0, 'setup: read failed; inventory unknown')
        try:
            require(len(result.stdout) <= 8 * 1024 * 1024, 'setup: response bound exceeded')
            data = json.loads(result.stdout, object_pairs_hook=unique_object)
            require(isinstance(data, dict), 'setup: malformed response')
            return data
        except (ValueError, TypeError):
            raise SetupError('setup: malformed response') from None


def verify_repository(config, reader):
    g = config['github']
    repo = reader.get('github', '/repos/' + g['repository'])
    require(repo.get('full_name') == g['repository'] and type(repo.get('id')) is int
            and str(repo['id']) == g['repositoryID'] and type(repo.get('owner', {}).get('id')) is int
            and str(repo['owner']['id']) == g['ownerID'], 'setup: GitHub target mismatch')


def collect_setup(config, reader=None, focus=None, readback=False):
    setup_configuration(config)
    reader = reader or SetupReader(config)
    account = reader.account()
    a = config['azure']
    require(account.get('id') == a['subscriptionID'] and account.get('tenantId') == a['tenantID']
            and account.get('state') == 'Enabled', 'setup: Azure target mismatch')
    if not readback:
        verify_repository(config, reader)
        oidc = reader.get('github', '/repos/' + config['github']['repository'] + '/actions/oidc/customization/sub')
        require(oidc.get('use_default') is True and oidc.get('use_immutable_subject') is True,
                'setup: immutable GitHub subject required')
    urls = setup_routes(config)
    # Reuse only unrelated collections within this operation. Target, ownership
    # parents and authorization edges are fresh before each write; no disk cache.
    if focus is None:
        reader.collections.clear()
        refresh = None
    elif readback:
        refresh = {
            'anchor': {'groups'}, 'clusterRG': {'groups'}, 'modelRG': {'groups'},
            'anchorSlots': {'groups'}, 'budget': {'budgets'}, 'ci': {'identities'},
            'model': {'identities'}, 'account': {'accounts'}, 'deployment': {'deployments'},
            'metadata': {'roles', 'rgRoles'}, 'federation': {'roles', 'rgRoles'},
            'ciFic': {'ciFics'},
        }.get(focus['key'], {'assignments', 'accountAssignments'})
        if focus['action'] == 'register':
            refresh = {'providers'}
        if focus['action'] == 'delete':
            refresh = refresh | {'resources'}
    else:
        refresh = {'groups', 'resources', 'roles', 'rgRoles', 'assignments', 'accountAssignments',
                   'identities', 'budgets', 'ciFics', 'modelFics'}
        if focus['action'] == 'register':
            refresh.add('providers')
        if focus['key'] in ('account', 'deployment', 'modelGrant'):
            refresh |= {'accounts', 'deletedAccounts', 'deployments'}
        if focus['key'] == 'ciFic':
            refresh = None  # full security read before activating CI federation

    def listing(key):
        if refresh is None or key in refresh or key not in reader.collections:
            reader.collections[key] = reader.paginated('arm', urls[key])
        return reader.collections[key]

    def missing(key):
        reader.collections.pop(key, None)
        return []
    state = {'tenantID': a['tenantID'], 'unavailable': [], 'oidc': {'use_default': True, 'use_immutable_subject': True}}
    for key in ('groups', 'resources', 'providers', 'roles', 'assignments'):
        state[key] = listing(key)
    groups = {x['id'].lower() for x in state['groups']}
    specs = resource_specs(config, state)
    targets = {s['key']: s['id'] for s in specs}
    registration = {p.get('namespace'): p.get('registrationState') for p in state['providers']}
    for provider in PROVIDERS:
        require(registration.get(provider) in ('Registered', 'NotRegistered', 'Registering', 'Unregistering'),
                'setup: provider state unknown')
    state['registration'] = registration
    for key, provider, parent in [
        ('identities', 'Microsoft.ManagedIdentity', targets['anchor']),
        ('accounts', 'Microsoft.CognitiveServices', None),
        ('deletedAccounts', 'Microsoft.CognitiveServices', None),
        ('budgets', 'Microsoft.Consumption', None), ('rgRoles', None, targets['anchor'])]:
        provider_unavailable = provider and registration[provider] != 'Registered'
        if provider_unavailable:
            state['unavailable'].append(key)
        state[key] = missing(key) if provider_unavailable or (parent and parent.lower() not in groups) else listing(key)
    state['roles'] = merge_objects(state['roles'] + state.pop('rgRoles'))
    for role in state['roles']:
        require(re.fullmatch(re.escape(root(config)) + r'/providers/Microsoft.Authorization/roleDefinitions/' + GUID,
                             role['id'], re.IGNORECASE), 'setup: role definition target mismatch')
    identity_ids = {x['id'].lower() for x in state['identities']}
    account_ids = {x['id'].lower() for x in state['accounts']}
    for key, parent in [('ciFics', targets['ci']), ('modelFics', targets['model']),
                        ('deployments', targets['account']), ('accountAssignments', targets['account'])]:
        exists = parent.lower() in (identity_ids if 'Fics' in key else account_ids)
        state[key] = listing(key) if exists else missing(key)
    state['assignments'] = merge_objects(state['assignments'] + state.pop('accountAssignments'))
    collections = ('groups', 'resources', 'roles', 'assignments', 'identities', 'accounts', 'budgets', 'ciFics', 'modelFics', 'deployments')
    state['objects'] = merge_objects([item for key in collections for item in state[key]], prefer_last=True)
    base = root(config).lower()
    for key in collections:
        for item in state[key]:
            target = item.get('id')
            # Inherited assignment scopes may be tenant/management-group scopes.
            if key == 'assignments':
                scope = item.get('properties', {}).get('scope')
                scope_valid = isinstance(scope, str) and (scope == '/' or scope.lower() == base
                    or scope.lower().startswith(base + '/') or re.fullmatch(
                        r'/providers/Microsoft.Management/managementGroups/[A-Za-z0-9][A-Za-z0-9_.()-]{0,89}', scope, re.IGNORECASE))
                require(scope_valid and isinstance(target, str) and re.fullmatch(
                    re.escape(scope.rstrip('/')) + r'/providers/Microsoft.Authorization/roleAssignments/' + GUID, target, re.IGNORECASE)
                    and valid_guid(item.get('properties', {}).get('principalId')),
                    'setup: assignment target mismatch')
            else:
                require(isinstance(target, str) and target.lower().startswith(base + '/'), 'setup: ARM target mismatch')
    for key, parent in [('ciFics', targets['ci']), ('modelFics', targets['model']), ('deployments', targets['account'])]:
        suffix = '/deployments/' if key == 'deployments' else '/federatedidentitycredentials/'
        require(all(x['id'].lower().startswith(parent.lower() + suffix) for x in state[key]), 'setup: child target mismatch')
    return state


def merge_objects(items, prefer_last=False):
    result = {}
    for item in items:
        require(isinstance(item, dict) and isinstance(item.get('id'), str), 'setup: malformed inventory')
        key = item['id'].lower()
        if key in result and not prefer_last:
            require(result[key] == item, 'setup: inconsistent duplicate inventory')
        result[key] = item
    return list(result.values())


def quiescence(config, reader):
    verify_repository(config, reader)
    repo = '/repos/' + config['github']['repository']
    variables = reader.paginated('github', repo + '/actions/variables?per_page=100&page=1', 'variables')
    values = {}
    for variable in variables:
        require(isinstance(variable.get('name'), str) and isinstance(variable.get('value'), str)
                and variable['name'] not in values, 'setup: invalid repository variables')
        values[variable['name']] = variable['value']
    subscription = values.get('AZURE_SUBSCRIPTION_ID', '').lower()
    cluster_group = values.get('AKS_RESOURCE_GROUP', '').lower()
    identity_group = values.get('AKS_IDENTITY_RESOURCE_GROUP', '').lower()
    different_subscription = bool(subscription) and subscription != config['azure']['subscriptionID'].lower()
    different_groups = (bool(cluster_group) and bool(identity_group)
                        and cluster_group != config['nightly']['resourceGroup'].lower()
                        and identity_group != config['nightly']['identityResourceGroup'].lower())
    # Missing repository values may fall back to organization vars in Actions.
    targeted = not (different_subscription or different_groups)
    require(not targeted or values.get('AKS_SCENARIO_ENABLED', '').lower() == 'false',
            'setup: scenario is enabled or not explicitly disabled')
    for workflow in ('aks-e2e.yml', 'aks-cleanup.yml'):
        for status in ('queued', 'in_progress', 'waiting', 'pending', 'requested'):
            path = repo + '/actions/workflows/' + workflow + '/runs?' + urlencode({'status': status, 'per_page': 100, 'page': 1})
            runs = reader.paginated('github', path, 'workflow_runs')
            require(not runs, 'setup: workflow is active')
    return {'targeted': targeted, 'scenarioDisabled': True, 'activeRuns': 0}


def verify_federation_policy(config, reader):
    """An environment subject is safe only with its independently verified branch gate."""
    repo = '/repos/' + config['github']['repository']
    environments = reader.paginated('github', repo + '/environments?per_page=100&page=1', 'environments')
    matches = [env for env in environments if isinstance(env.get('name'), str)
               and env['name'].casefold() == 'nightly-aks']
    require(len(matches) == 1, 'setup: main-only nightly environment required')
    environment = matches[0]
    require(environment.get('deployment_branch_policy') == {'protected_branches': False, 'custom_branch_policies': True}
            and isinstance(environment.get('protection_rules'), list)
            and all(isinstance(rule, dict) and rule.get('type') == 'branch_policy' for rule in environment['protection_rules']),
            'setup: main-only nightly environment required')
    path = repo + '/environments/' + environment_segment(environment['name']) + '/deployment-branch-policies'
    policies = reader.paginated('github', path + '?per_page=100&page=1', 'branch_policies')
    require(len(policies) == 1 and policies[0].get('name') == 'main' and policies[0].get('type') == 'branch',
            'setup: main-only nightly environment required')


def object_for(spec, state, specs):
    item = find(state, spec['id'])
    if item is None and spec['kind'] == 'grant':
        expected = resolved_body(spec, state, specs)['properties']
        matches = [x for x in state['assignments'] if all(
            x.get('properties', {}).get(k) == expected[k] for k in ('principalId', 'roleDefinitionId', 'scope'))]
        if len(matches) == 1:
            item = matches[0]
    return item


def reservations(config, state, specs):
    anchor = find(state, next(s['id'] for s in specs if s['key'] == 'anchor'))
    tags = (anchor or {}).get('tags', {})
    result = {slot(s['key']): s['id'].rsplit('/', 1)[-1] for s in specs
              if s['kind'] in ('budget', 'role', 'grant', 'fic') and object_for(s, state, specs) is None
              and slot(s['key']) not in tags}
    if result:
        result[CONFIG_TAG] = topology_digest(config)
    return result


def state_digest(config, state):
    """Safety-relevant topology, not subscription noise or spend telemetry."""
    specs = resource_specs(config, state)
    targets = {s['id'].lower() for s in specs}
    principals = {item.get('properties', {}).get('principalId')
                  for s in specs if s['key'] in ('ci', 'model') and (item := find(state, s['id']))}
    prefixes = [item['id'].lower() + '/' for item in state['objects']
                if ownership(item, config)[0] == 'owned']
    roles = {s['id'].lower() for s in specs if s['kind'] == 'role'}
    account = next(s['id'].lower() for s in specs if s['key'] == 'account')

    def relevant(item):
        target = item['id'].lower()
        properties = item.get('properties', {})
        return (target in targets or any(target.startswith(p) for p in prefixes)
                or ownership(item, config)[0] != 'reference'
                or properties.get('principalId') in principals
                or properties.get('roleDefinitionId', '').lower() in roles
                or properties.get('scope', '').lower() == account)

    def stable(value):
        if isinstance(value, dict):
            return {k: stable(v) for k, v in value.items()
                    if k not in ('currentSpend', 'forecastSpend', 'systemData', 'etag')}
        if isinstance(value, list):
            return sorted((stable(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
        return value

    return digest(stable({'objects': [x for x in state['objects'] if relevant(x)],
                          'registration': {p: state['registration'][p] for p in PROVIDERS},
                          'unavailable': state['unavailable'], 'oidc': state['oidc']}))


def ownership_state(config, spec, item):
    if item is None:
        return 'absent'
    state, component = ownership(item, config)
    if state == 'owned':
        expected = markers(config, spec['ownerRole'])
        require(component == expected['ada-bootstrap-component'] and subset(expected, item.get('tags', {})),
                'setup: ownership role mismatch')
    require(state != 'blocked', 'setup: ambiguous ownership markers')
    return state


def build_plan(config, state, operation, include_shared=False):
    setup_configuration(config)
    require(operation in ('apply', 'destroy') and (not include_shared or operation == 'destroy'))
    specs = resource_specs(config, state)
    by_key = {s['key']: s for s in specs}
    anchor = find(state, by_key['anchor']['id'])
    anchor_owned = ownership_state(config, by_key['anchor'], anchor) == 'owned'
    tags = anchor.get('tags', {}) if anchor else {}
    blockers, actions, retained = [], [], []
    desired_tags = {}
    states, objects = {}, {}

    def block(reason):
        if reason not in blockers:
            blockers.append(reason)

    # Only the fixed, topology-derived slots can confer ownership.
    slot_specs = [s for s in specs if s['kind'] in ('budget', 'role', 'grant', 'fic')]
    allowed_slots = {slot(s['key']): identifier(config, s['key']) if s['kind'] in ('role', 'grant')
                     else s['id'].rsplit('/', 1)[-1] for s in slot_specs}
    if len(tags) > 50 or any(not isinstance(k, str) or not isinstance(v, str) or len(v) > 256 for k, v in tags.items()):
        block('invalid-anchor-tags')
    for key, value in tags.items():
        if key.lower().startswith(SLOT_PREFIX) and (not anchor_owned or key not in allowed_slots or allowed_slots[key] != value):
            block('conflicting-anchor-slot')
    if anchor_owned and tags.get(CONFIG_TAG) not in (None, topology_digest(config)):
        block('configuration-drift')
    for spec in specs:
        item = find(state, spec['id'])
        if spec['kind'] == 'grant':
            expected = resolved_body(spec, state, specs)['properties']
            matches = [x for x in state['assignments'] if all(
                x.get('properties', {}).get(k) == expected[k] for k in ('principalId', 'roleDefinitionId', 'scope'))]
            if len(matches) > 1:
                block('duplicate-grant')
            if matches and item is None:
                item = matches[0]
        if spec['kind'] == 'role':
            matches = [x for x in state['roles'] if x.get('properties', {}).get('roleName') == spec['body']['properties']['roleName']]
            if len(matches) > 1:
                block('role-name-collision')
        objects[spec['key']] = item
        if spec['ownerRole']:
            status = ownership_state(config, spec, item)
        elif item is None:
            status = 'absent'
        elif spec['kind'] == 'deployment':
            account_tags = (objects.get('account') or {}).get('tags', {})
            status = 'owned' if states.get('account') == 'owned' and account_tags.get(DEPLOYMENT_TAG) == config['model']['deploymentName'] else 'reference'
        else:
            status = 'owned' if (anchor_owned and tags.get(slot(spec['key'])) == allowed_slots[slot(spec['key'])]
                                 and item['id'].lower() == spec['id'].lower()
                                 and item['id'].rsplit('/', 1)[-1] == allowed_slots[slot(spec['key'])]
                                 and (spec['kind'] != 'fic' or states.get('ci') == 'owned')) else 'reference'
        states[spec['key']] = status
        if item and not matching(spec, item, state, specs):
            block('resource-configuration-mismatch:' + spec['key'])
        if item and status == 'reference' and slot(spec['key']) in tags:
            block('reserved-target-conflict')
        if status == 'absent' and spec['kind'] in ('budget', 'role', 'grant', 'fic') and slot(spec['key']) not in tags:
            desired_tags[slot(spec['key'])] = allowed_slots[slot(spec['key'])]
    expected_ids = {s['id'].lower() for s in specs}
    for item in state['objects']:
        status, component = ownership(item, config)
        if status == 'blocked':
            block('ambiguous-owner-markers')
        if status == 'owned' and component in ('nightly', 'shared-model') and item['id'].lower() not in expected_ids:
            block('unexpected-owned-target')
    for deleted in state['deletedAccounts']:
        if (operation == 'apply' and states['account'] == 'absent' and
                (deleted.get('name', '').split('/')[-1].lower() == config['model']['accountName'].lower()
                 or deleted.get('properties', {}).get('customSubDomainName', '').lower() == config['model']['accountName'].lower())):
            block('soft-deleted-account')
    if states.get('account') == 'owned' and any(x['id'].lower() != by_key['deployment']['id'].lower() for x in state['deployments']):
        block('unexpected-model-deployment')
    if state['modelFics']:
        block('runtime-model-federation-present')
    if any(x['id'].lower() != by_key['ciFic']['id'].lower() for x in state['ciFics']):
        block('unexpected-ci-federation')
    principal_ids = {x.get('properties', {}).get('principalId') for key in ('ci', 'model') if (x := objects[key])}
    expected_grants = {objects[s['key']]['id'].lower() for s in specs if s['kind'] == 'grant' and objects[s['key']]}
    for grant in state['assignments']:
        p = grant.get('properties', {})
        if p.get('principalId') in principal_ids and grant['id'].lower() not in expected_grants:
            block('unexpected-identity-grant')
        if any(p.get('roleDefinitionId', '').lower() == by_key[k]['id'].lower() for k in ('metadata', 'federation')) and grant['id'].lower() not in expected_grants:
            block('unexpected-role-consumer')
    # Reservations retain fixed UUIDs when a principal was manually recreated.
    for spec in specs:
        if spec['kind'] == 'grant' and objects[spec['key']] and not matching(spec, objects[spec['key']], state, specs):
            block('orphaned-grant')
    for item in state['groups']:
        if item['id'].lower() == (root(config) + '/resourceGroups/' + config['nightly']['nodeResourceGroup']).lower():
            block('managed-node-group-present')
    cluster_prefix = by_key['clusterRG']['id'].lower() + '/'
    if any(x['id'].lower().startswith(cluster_prefix) for x in state['resources']):
        block('cluster-group-not-empty')

    def action(spec, verb, body=None):
        result = {'action': verb, 'key': spec['key'], 'id': spec['id'], 'apiVersion': spec['version'],
                  'bodyDigest': digest(spec['body'] if body is None else body)}
        if spec.get('kind') == 'role':
            result['authorization'] = spec['body']['properties']
        elif spec.get('kind') == 'grant':
            p = spec['body']['properties']
            result['authorization'] = {'principalIdentityID': by_key[p['principalId'][1:]]['id'],
                                       'roleDefinitionID': p['roleDefinitionId'], 'scope': p['scope'],
                                       'principalType': 'ServicePrincipal'}
        elif spec.get('kind') == 'fic':
            result['authorization'] = spec['body']['properties']
        return result

    if any(budget.get('properties', {}).get(field, {}).get('unit') not in (None, '', 'USD')
           for budget in state['budgets'] for field in ('currentSpend', 'forecastSpend')):
        block('observed-currency-is-not-usd')
    if operation == 'apply':
        budget = config['setup']['budget']
        today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        if not budget['startDate'] <= today < budget['endDate']:
            block('budget-period-not-active')
        if states['budget'] == 'absent' and config['setup']['budget']['startDate'] != datetime.datetime.now(datetime.timezone.utc).date().replace(day=1).isoformat():
            block('new-budget-requires-current-month')
        for namespace in PROVIDERS:
            registration = state['registration'][namespace]
            if registration != 'Registered':
                if registration == 'NotRegistered' and namespace in config['setup']['registerProviders']:
                    actions.append({'action': 'register', 'key': namespace, 'id': root(config) + '/providers/' + namespace,
                                    'apiVersion': '2021-04-01', 'bodyDigest': digest({})})
                else:
                    block('provider-not-ready')
        if desired_tags:
            if anchor is not None and not anchor_owned:
                block('anchor-is-reference')
            desired_tags[CONFIG_TAG] = topology_digest(config)
            if len(set(tags) | set(desired_tags)) > 50:
                block('anchor-tag-capacity')
        for spec in specs:
            if states[spec['key']] != 'absent':
                continue
            if config['setup']['modelMode'] == 'reference' and spec['key'] in ('modelRG', 'account', 'deployment'):
                block('model-reference-missing')
                continue
            if spec['kind'] == 'grant':
                principal = spec['body']['properties']['principalId'][1:]
                if states[principal] == 'reference':
                    block('grant-principal-is-reference')
            parent = next((s for s in specs if s['id'] == spec['parent']), None)
            if parent and states[parent['key']] == 'reference':
                block('creation-parent-is-reference')
            body = spec['body']
            if spec['key'] == 'anchor':
                body = dict(body, tags=dict(body['tags'], **desired_tags))
            actions.append(action(spec, 'create', body))
        if anchor_owned and desired_tags:
            metadata = {'key': 'anchorSlots', 'id': by_key['anchor']['id'] + '/providers/Microsoft.Resources/tags/default',
                        'version': '2021-04-01', 'body': {'operation': 'Merge', 'properties': {'tags': desired_tags}}}
            actions.insert(sum(a['action'] == 'register' for a in actions), action(metadata, 'merge'))
    else:
        if state['unavailable'] or any(state['registration'][p] != 'Registered' for p in PROVIDERS):
            block('provider-not-ready')
        # Never delete a broad group to dispose of an unknown descendant.
        deleting = {s['id'].lower() for s in specs if states[s['key']] == 'owned' and (include_shared or not s['shared'])}
        for spec in specs:
            status = states[spec['key']]
            if status == 'absent':
                continue
            keep = status != 'owned' or (spec['shared'] and not include_shared)
            if spec['key'] == 'anchor' and not include_shared:
                keep = True
            if keep:
                retained.append({'id': objects[spec['key']]['id'], 'reason': 'reference' if status != 'owned' else 'shared-default'})
                deleting.discard(spec['id'].lower())
            else:
                actions.append(action(spec, 'delete'))
        owned_prefixes = [s['id'].lower() + '/' for s in specs if s['kind'] in ('group', 'account', 'identity') and s['id'].lower() in deleting]
        for item in state['objects']:
            target = item['id'].lower()
            if any(target.startswith(prefix) for prefix in owned_prefixes) and target not in deleting:
                block('external-or-retained-child')
        for role in state['roles']:
            scopes = role.get('properties', {}).get('assignableScopes', [])
            if any(isinstance(scope, str) and scope.lower() in deleting for scope in scopes) and role['id'].lower() not in deleting:
                block('external-role-scope')
        if include_shared and by_key['account']['id'].lower() in deleting:
            for grant in state['assignments']:
                scope = grant.get('properties', {}).get('scope', '').lower()
                if scope == by_key['account']['id'].lower() and grant['id'].lower() not in deleting:
                    block('external-model-grant')
        priority = {'fic': 0, 'grant': 1, 'deployment': 2, 'role': 3, 'identity': 4, 'account': 5, 'budget': 6, 'group': 7}
        actions.sort(key=lambda a: (9 if a['key'] == 'anchor' else priority[by_key[a['key']]['kind']]))
    result = {'version': 1, 'command': operation, 'environmentID': config['environmentID'],
              'subscriptionID': config['azure']['subscriptionID'], 'tenantID': config['azure']['tenantID'],
              'configDigest': digest(config), 'stateDigest': state_digest(config, state), 'includeShared': include_shared, 'actions': actions,
              'blockers': sorted(blockers), 'retained': retained, 'ready': False,
              'quiescence': state.get('quiescence') if actions else None}
    n, m = config['nightly'], config['model']
    result['summary'] = {'repositoryVariables': {
        'AKS_BOOTSTRAP_ENABLED': 'false', 'AKS_SCENARIO_ENABLED': 'false', 'AKS_BUDGET_CONFIRMED': 'false',
        'AZURE_TENANT_ID': config['azure']['tenantID'], 'AZURE_SUBSCRIPTION_ID': config['azure']['subscriptionID'],
        'AKS_RESOURCE_GROUP': n['resourceGroup'], 'AKS_IDENTITY_RESOURCE_GROUP': n['identityResourceGroup'],
        'AKS_NODE_RESOURCE_GROUP': n['nodeResourceGroup'], 'AKS_CLUSTER_NAME': n['clusterName'],
        'AKS_MODEL_IDENTITY_NAME': n['modelIdentityName'], 'MODEL_DEPLOYMENT': m['deploymentName'],
        'MODEL_ENDPOINT': 'https://' + m['accountName'] + '.openai.azure.com/openai/v1/'},
        'principals': {key: item['properties']['principalId'] for key in ('ci', 'model')
                       if (item := objects[key]) and matching(by_key[key], item, state, specs)}}
    if objects['ci'] and matching(by_key['ci'], objects['ci'], state, specs):
        result['summary']['repositoryVariables']['AZURE_CLIENT_ID'] = objects['ci']['properties']['clientId']
    result['planDigest'] = digest(result)
    return result


def plan_setup(config, operation, include_shared=False, reader=None):
    reader = reader or SetupReader(config)
    state = collect_setup(config, reader)
    plan = build_plan(config, state, operation, include_shared)
    if operation == 'apply' and any(action['key'] == 'ciFic' for action in plan['actions']):
        verify_federation_policy(config, reader)
    if plan['actions']:
        state['quiescence'] = quiescence(config, reader)
        plan = build_plan(config, state, operation, include_shared)
    return plan


def read_plan(path):
    """Open once, reject symlinks/races, and bound bytes before parsing."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) & 0o077 == 0 and info.st_size <= 1024 * 1024,
                    'setup: plan must be owner-private regular file')
            raw = stream.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, 'setup: plan too large')
        result = json.loads(raw, object_pairs_hook=unique_object)
        require(isinstance(result, dict), 'setup: invalid plan')
        return result
    except (OSError, ValueError, UnicodeError):
        raise SetupError('setup: invalid or unreadable private plan') from None


@contextmanager
def operation_lock(config):
    directory = Path(config['azure']['configDir'])
    path = directory / ('.bootstrap-' + config['environmentID'] + '.lock')
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(fd, 'a') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) & 0o077 == 0, 'setup: unsafe operation lock')
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise SetupError('setup: operation is locked') from None
            yield
    except OSError:
        raise SetupError('setup: operation lock unavailable') from None


class SetupTransport(SetupReader):
    def mutate(self, config, spec, verb, body):
        """Private fixed-spec transport; supplied plan data never reaches this method."""
        require(time.monotonic() < self.deadline, 'setup: deadline exceeded')
        method = {'create': 'PUT', 'delete': 'DELETE', 'register': 'POST', 'merge': 'PATCH'}[verb]
        suffix = '/register' if verb == 'register' else ''
        url = ARM + spec['id'] + suffix + '?api-version=' + spec['version']
        args = ['az', 'rest', '--method', method, '--url', url, '--subscription', config['azure']['subscriptionID'],
                '--only-show-errors', '--output', 'json']
        if verb != 'delete':
            args += ['--body', '@/dev/stdin', '--headers', 'Content-Type=application/json']
            if verb == 'create':
                args += ['If-None-Match=*']
        environment = dict(os.environ, AZURE_CONFIG_DIR=config['azure']['configDir'],
                           AZURE_EXTENSION_USE_DYNAMIC_INSTALL='no', AZURE_CORE_COLLECT_TELEMETRY='no')
        try:
            result = subprocess.run(args, input=json.dumps(body) if verb != 'delete' else None,
                                    capture_output=True, text=True, timeout=min(30, max(0.01, self.deadline - time.monotonic())),
                                    check=False, env=environment)
        except (OSError, subprocess.TimeoutExpired):
            raise SetupError('setup: ambiguous write; re-plan required') from None
        require(result.returncode == 0, 'setup: write failed or ambiguous; re-plan required')


def execute(config, approved_plan, transport=None):
    transport = transport or SetupTransport(config)
    require(approved_plan.get('command') in ('apply', 'destroy') and type(approved_plan.get('includeShared')) is bool,
            'setup: invalid approved plan')
    operation, include_shared = approved_plan['command'], approved_plan['includeShared']
    with operation_lock(config):
        fresh = plan_setup(config, operation, include_shared, transport)
        require(fresh == approved_plan and not fresh['blockers'], 'setup: stale, tampered or blocked plan')
        pending = list(fresh['actions'])
        if pending:
            quiescence(config, transport)
        completed = []
        observed_digest = fresh['stateDigest']
        for expected in pending:
            require(time.monotonic() < transport.deadline, 'setup: deadline exceeded')
            if expected['key'] == 'ciFic' and operation == 'apply':
                quiescence(config, transport)
            state = collect_setup(config, transport, focus=expected)
            current = build_plan(config, state, operation, include_shared)
            require(current['stateDigest'] == observed_digest and not current['blockers']
                    and current['actions'] and current['actions'][0] == expected,
                    'setup: state changed before write')
            specs = resource_specs(config, state)
            spec: dict = next((s for s in specs if s['key'] == expected['key']), {})
            verb = expected['action']
            body: dict
            if verb == 'register':
                spec = {'id': root(config) + '/providers/' + expected['key'], 'version': '2021-04-01'}
                body = {}
            elif verb == 'merge':
                anchor = next(s for s in specs if s['key'] == 'anchor')
                tags = reservations(config, state, specs)
                spec = {'id': anchor['id'] + '/providers/Microsoft.Resources/tags/default', 'version': '2021-04-01'}
                body = {'operation': 'Merge', 'properties': {'tags': tags}}
            else:
                require(bool(spec), 'setup: unknown resource specification')
                body = resolved_body(spec, state, specs)
                if spec['key'] == 'anchor' and verb == 'create':
                    tags = reservations(config, state, specs)
                    body['tags'].update(tags)
                if verb == 'create' and spec['kind'] == 'grant':
                    require(not body['properties']['principalId'].startswith('$'), 'setup: principal not ready')
                if operation == 'destroy' and spec['kind'] == 'group':
                    quiescence(config, transport)
                    state = collect_setup(config, transport)
                    require(state_digest(config, state) == observed_digest, 'setup: state changed before group delete')
                    prefix = spec['id'].lower() + '/'
                    require(not any(x['id'].lower().startswith(prefix) for x in state['objects']), 'setup: group not empty')
            approved_body = json.loads(json.dumps(body))
            if spec.get('kind') == 'grant':
                approved_body['properties']['principalId'] = spec['body']['properties']['principalId']
            require(digest(approved_body) == expected['bodyDigest'], 'setup: request body differs from approval')
            if verb == 'create' and expected['key'] == 'ciFic':
                verify_federation_policy(config, transport)
            transport.mutate(config, spec, verb, body)
            # Poll reads only; never repeat an ambiguous mutation or roll it back.
            while True:
                require(time.monotonic() < transport.deadline, 'setup: deadline exceeded during readback')
                after = collect_setup(config, transport, focus=expected, readback=True)
                if verb == 'register':
                    done = after['registration'][expected['key']] == 'Registered'
                elif verb == 'merge':
                    anchor_id = next(s['id'] for s in specs if s['key'] == 'anchor')
                    done = subset(body['properties']['tags'], (find(after, anchor_id) or {}).get('tags', {}))
                elif verb == 'delete':
                    done = find(after, spec['id']) is None
                else:
                    item = find(after, spec['id'])
                    done = bool(item and matching(spec, item, after, resource_specs(config, after))
                                and subset(body.get('tags', {}), item.get('tags', {})))
                if done:
                    break
                # Failed/unknown states cannot be treated as absence or retried writes.
                item = find(after, spec['id'])
                if item:
                    allowed_states = ('Creating', 'Updating', 'Deleting', 'Accepted') + (('Succeeded',) if verb == 'delete' else ())
                    require(item.get('properties', {}).get('provisioningState', 'Succeeded') in allowed_states,
                            'setup: readback mismatch; re-plan required')
                time.sleep(min(1, max(0, transport.deadline - time.monotonic())))
            observed_digest = state_digest(config, after)
            completed.append({'key': expected['key'], 'action': verb, 'id': expected['id']})
        final = build_plan(config, collect_setup(config, transport), operation, include_shared)
        require(not final['actions'] and not final['blockers'], 'setup: final readback incomplete; re-plan required')
        return {'version': 1, 'command': operation, 'ready': False, 'status': 'applied',
                'completed': completed, 'retained': fresh['retained']}
