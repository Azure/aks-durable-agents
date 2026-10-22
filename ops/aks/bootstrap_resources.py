"""Fixed Azure setup resources, exact relationships and cloud ownership slots."""
import hashlib
import json
import uuid

PROVIDERS = ('Microsoft.ContainerService', 'Microsoft.Compute', 'Microsoft.Network',
             'Microsoft.Storage', 'Microsoft.ManagedIdentity', 'Microsoft.CognitiveServices',
             'Microsoft.Consumption')
METADATA = ['Microsoft.Resources/subscriptions/read', 'Microsoft.Resources/subscriptions/providers/read',
            'Microsoft.Resources/subscriptions/resourceGroups/read', 'Microsoft.Compute/locations/usages/read',
            'Microsoft.ContainerService/locations/kubernetesversions/read',
            'Microsoft.ContainerService/locations/operations/read',
            'Microsoft.ContainerService/locations/operationresults/read']
FEDERATION = ['Microsoft.ManagedIdentity/userAssignedIdentities/read',
              'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read',
              'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write',
              'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/delete']
ROLE_NAMES = ('ADA Nightly Metadata Reader', 'ADA Nightly Model Federation Editor')
SLOT_PREFIX = 'ada-bootstrap-slot-'
OWNER = 'ada-bootstrap-role'
CONFIG_TAG = 'ada-bootstrap-config'
DEPLOYMENT_TAG = 'ada-bootstrap-deployment'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def topology_digest(config):
    return digest({'environmentID': config['environmentID'],
                   'azure': {k: config['azure'][k] for k in ('tenantID', 'subscriptionID')},
                   'repositoryID': config['github']['repositoryID'],
                   'nightly': config['nightly'],
                   'model': {k: config['model'][k] for k in ('resourceGroup', 'accountName', 'deploymentName')}})


def root(config):
    return '/subscriptions/' + config['azure']['subscriptionID']


def markers(config, role):
    shared = role in ('sharedModelRG', 'modelAccount')
    tags = {'ada-bootstrap-environment': config['environmentID'],
            'ada-repository-id': config['github']['repositoryID'],
            'ada-bootstrap-component': 'shared-model' if shared else 'nightly', OWNER: role}
    if not shared:
        tags['ada-purpose'] = 'nightly-aks'
    if role == 'modelAccount':
        tags[DEPLOYMENT_TAG] = config['model']['deploymentName']
    return tags


def slot(key):
    return SLOT_PREFIX + key


def identifier(config, key):
    return str(uuid.uuid5(uuid.UUID(config['environmentID']), root(config).lower() + ':' + key))


def resource_specs(config, state):
    """Closed topology. Grant bodies use symbolic principals until ARM assigns them."""
    n, m, s = config['nightly'], config['model'], config['setup']
    base = root(config)
    cluster = base + '/resourceGroups/' + n['resourceGroup']
    anchor = base + '/resourceGroups/' + n['identityResourceGroup']
    model_rg = base + '/resourceGroups/' + m['resourceGroup']
    ci = anchor + '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/' + n['ciIdentityName']
    model = anchor + '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/' + n['modelIdentityName']
    account = model_rg + '/providers/Microsoft.CognitiveServices/accounts/' + m['accountName']
    specs = []

    def add(key, kind, target, version, body, parent=None, shared=False, role=None):
        specs.append({'key': key, 'kind': kind, 'id': target, 'version': version,
                      'body': body, 'parent': parent, 'shared': shared, 'ownerRole': role})

    # The anchor precedes the budget; the budget precedes any model costs.
    add('anchor', 'group', anchor, '2021-04-01',
        {'location': 'westus3', 'tags': markers(config, 'identityAnchor')}, role='identityAnchor')
    b = s['budget']
    notifications = {}
    for label, threshold, kind in [('actual50', 50, 'Actual'), ('actual80', 80, 'Actual'),
                                   ('actual100', 100, 'Actual'), ('forecasted100', 100, 'Forecasted')]:
        notifications[label] = {'enabled': True, 'operator': 'GreaterThanOrEqualTo', 'threshold': threshold,
                                'thresholdType': kind, 'contactEmails': [b['email']],
                                'contactGroups': [], 'contactRoles': [], 'locale': 'en-us'}
    add('budget', 'budget', base + '/providers/Microsoft.Consumption/budgets/' + b['name'], '2024-08-01',
        {'properties': {'amount': 100, 'category': 'Cost', 'timeGrain': 'Monthly',
                        'timePeriod': {'startDate': b['startDate'] + 'T00:00:00Z',
                                       'endDate': b['endDate'] + 'T00:00:00Z'},
                        'notifications': notifications}}, parent=anchor, shared=True)
    for key, target, role, shared in [('clusterRG', cluster, 'clusterRG', False),
                                       ('modelRG', model_rg, 'sharedModelRG', True)]:
        add(key, 'group', target, '2021-04-01', {'location': m['location'] if shared else 'westus3', 'tags': markers(config, role)},
            shared=shared, role=role)
    add('account', 'account', account, '2024-10-01',
        {'location': m['location'], 'kind': 'OpenAI', 'sku': {'name': 'S0'},
         'tags': markers(config, 'modelAccount'),
         'properties': {'disableLocalAuth': True, 'publicNetworkAccess': 'Enabled',
                        'customSubDomainName': m['accountName']}}, parent=model_rg, shared=True, role='modelAccount')
    add('deployment', 'deployment', account + '/deployments/' + m['deploymentName'], '2024-10-01',
        {'sku': {'name': m['sku'], 'capacity': m['capacity']},
         'properties': {'model': {'format': 'OpenAI', 'name': s['modelName'], 'version': m['version']},
                        'raiPolicyName': 'Microsoft.DefaultV2',
                        'versionUpgradeOption': 'OnceNewDefaultVersionAvailable'}}, parent=account, shared=True)
    for key, target, role in [('ci', ci, 'ciIdentity'), ('model', model, 'modelIdentity')]:
        add(key, 'identity', target, '2023-01-31',
            {'location': 'westus3', 'tags': markers(config, role)}, parent=anchor, role=role)
    role_ids = []
    for index, (key, actions, scope) in enumerate([('metadata', METADATA, base), ('federation', FEDERATION, anchor)]):
        matches = [r for r in state.get('roles', []) if r.get('properties', {}).get('roleName') == ROLE_NAMES[index]]
        target = matches[0]['id'] if len(matches) == 1 else base + '/providers/Microsoft.Authorization/roleDefinitions/' + identifier(config, key)
        role_ids.append(target)
        add(key, 'role', target, '2022-04-01',
            {'properties': {'roleName': ROLE_NAMES[index], 'type': 'CustomRole', 'assignableScopes': [scope],
                            'permissions': [{'actions': actions, 'notActions': [], 'dataActions': [], 'notDataActions': []}]}}, parent=anchor)
    grants = [('aksContributor', 'ci', cluster, base + '/providers/Microsoft.Authorization/roleDefinitions/ed7f3fbd-7b88-4dd4-9017-9adb7ce333f8'),
              ('aksAdmin', 'ci', cluster, base + '/providers/Microsoft.Authorization/roleDefinitions/b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b'),
              ('metadataGrant', 'ci', base, role_ids[0]), ('federationGrant', 'ci', model, role_ids[1]),
              ('modelGrant', 'model', account, base + '/providers/Microsoft.Authorization/roleDefinitions/5e0bd9bd-7b93-4f28-af87-19fc36ad61bd')]
    for key, principal, scope, role_id in grants:
        props = {'principalId': '$' + principal, 'principalType': 'ServicePrincipal',
                 'roleDefinitionId': role_id, 'scope': scope}
        add(key, 'grant', scope + '/providers/Microsoft.Authorization/roleAssignments/' + identifier(config, key),
            '2022-04-01', {'properties': props}, parent=anchor)
    g = config['github']
    owner, repository = g['repository'].split('/')
    subject = f"repo:{owner}@{g['ownerID']}/{repository}@{g['repositoryID']}:environment:nightly-aks"
    add('ciFic', 'fic', ci + '/federatedIdentityCredentials/github-nightly-aks', '2023-01-31',
        {'properties': {'issuer': 'https://token.actions.githubusercontent.com', 'subject': subject,
                        'audiences': ['api://AzureADTokenExchange']}}, parent=ci)
    return specs


def resolved_body(spec, state, specs):
    body = json.loads(json.dumps(spec['body']))
    if spec['kind'] == 'grant':
        key = body['properties']['principalId'][1:]
        target = next(s['id'] for s in specs if s['key'] == key)
        identity = find(state, target)
        if identity:
            body['properties']['principalId'] = identity.get('properties', {}).get('principalId')
    return body


def find(state, target):
    for item in state.get('objects', []):
        if item['id'].lower() == target.lower():
            return item
    return None


def subset(expected, actual):
    """ARM adds read-only properties; configured collections remain exact."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and subset(v, actual[k]) for k, v in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(expected) == len(actual) and all(v in actual for v in expected)
    if isinstance(expected, bool) or isinstance(actual, bool):
        return type(expected) is type(actual) and expected == actual
    return expected == actual


def matching(spec, item, state, specs):
    body = resolved_body(spec, state, specs)
    if spec['key'] == 'modelRG' and not subset(body.get('tags', {}), item.get('tags', {})):
        body.pop('location', None)  # RG metadata location need not match an existing account region.
    body.pop('tags', None)
    if spec['kind'] == 'grant':
        body['properties'].pop('scope', None)  # scope is also encoded in the exact ARM ID
        if item.get('properties', {}).get('condition') or item.get('properties', {}).get('conditionVersion'):
            return False
    if not subset(body, item):
        return False
    props = item.get('properties', {})
    if props.get('provisioningState', 'Succeeded') != 'Succeeded':
        return False
    if spec['kind'] == 'budget':
        return (not props.get('filter') and all(props.get(k, {}).get('unit') in (None, '', 'USD') for k in ('currentSpend', 'forecastSpend'))
                and set(props.get('notifications', {})) == set(body['properties']['notifications']))
    if spec['kind'] == 'account':
        return props.get('endpoint') == 'https://' + spec['id'].rsplit('/', 1)[-1] + '.openai.azure.com/'
    if spec['kind'] == 'identity':
        from bootstrap_inventory import valid_guid
        return (valid_guid(props.get('clientId')) and valid_guid(props.get('principalId'))
                and props.get('tenantId') == state['tenantID'])
    return True
