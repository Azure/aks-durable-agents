"""Offline setup safety contracts; synthetic public targets only."""
import copy
import datetime
import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import bootstrap
import bootstrap_inventory as inventory
import bootstrap_resources as resources
import bootstrap_setup as setup
from test_bootstrap import CONFIG


def configuration():
    config = copy.deepcopy(CONFIG)
    today = datetime.datetime.now(datetime.timezone.utc).date().replace(day=1)
    config['setup'] = {
        'modelMode': 'create', 'modelName': 'test-model',
        'registerProviders': list(resources.PROVIDERS),
        'budget': {'name': 'test-guard', 'amount': 100, 'currency': 'USD',
                   'email': 'operator@example.invalid', 'startDate': today.isoformat(),
                   'endDate': today.replace(year=today.year + 1).isoformat()}}
    return config


class Cloud:
    """Stateful ARM wire exercising real argv, stdin transport and collection routes."""
    def __init__(self, config):
        self.config = config
        self.objects = {}
        self.writes = []
        self.calls = []
        self.providers = {p: 'Registered' for p in resources.PROVIDERS}
        self.variables = {'AKS_SCENARIO_ENABLED': 'false'}
        self.runs = {}
        self.fail_write = None
        self.after_write = None
        self.repo = {'full_name': 'example/agents', 'id': 12345, 'owner': {'id': 67890}}
        self.oidc = {'use_default': True, 'use_immutable_subject': True}
        self.deleted_accounts = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[:3] == ['az', 'account', 'show']:
            data = {'id': self.config['azure']['subscriptionID'],
                    'tenantId': self.config['azure']['tenantID'], 'state': 'Enabled'}
            return subprocess.CompletedProcess(args, 0, json.dumps(data), '')
        method = args[args.index('--method') + 1]
        url = args[args.index('--url') + 1] if args[0] == 'az' else args[args.index(method) + 1]
        path = urlsplit(url).path
        if method != 'GET':
            self.writes.append((method, path, kwargs.get('input')))
            if self.fail_write == len(self.writes):
                return subprocess.CompletedProcess(args, 1, 'PRIVATE RAW OUTPUT', 'PRIVATE ERROR')
            body: dict = json.loads(kwargs['input']) if kwargs.get('input') else {}
            if method == 'POST':
                self.providers[path.rsplit('/', 2)[-2]] = 'Registered'
            elif method == 'PATCH':
                parent = path.removesuffix('/providers/Microsoft.Resources/tags/default')
                self.objects[parent]['tags'].update(body['properties']['tags'])
            elif method == 'DELETE':
                del self.objects[path]
            else:
                if path in self.objects:
                    return subprocess.CompletedProcess(args, 1, '', '409 conflict')
                item = dict(body, id=path, name=path.rsplit('/', 1)[-1])
                if '/userAssignedIdentities/' in path and '/' not in path.split('/userAssignedIdentities/')[1]:
                    index = 4 if item['name'] == 'ci' else 5
                    value = str(index) * 8 + '-' + str(index) * 4 + '-4' + str(index) * 3 + '-8' + str(index) * 3 + '-' + str(index) * 12
                    item['properties'] = {'principalId': value, 'clientId': value, 'tenantId': self.config['azure']['tenantID']}
                if '/accounts/' in path and '/' not in path.split('/accounts/')[1]:
                    item['properties']['endpoint'] = 'https://' + item['name'] + '.openai.azure.com/'
                self.objects[path] = item
            if self.after_write:
                self.after_write(len(self.writes), self)
            return subprocess.CompletedProcess(args, 0, '{}', '')
        urls = setup.setup_routes(self.config)
        label = next((k for k, value in urls.items() if urlsplit(value).path == path), None)
        objects = list(self.objects.values())
        if path == '/repos/example/agents':
            data = self.repo
        elif path.endswith('/actions/oidc/customization/sub'):
            data = self.oidc
        elif path.endswith('/actions/variables'):
            data = {'variables': [{'name': k, 'value': v} for k, v in self.variables.items()], 'total_count': len(self.variables)}
        elif '/actions/workflows/' in path:
            workflow = path.split('/')[-2]
            status = parse_qs(urlsplit(url).query)['status'][0]
            runs = self.runs.get((workflow, status), [])
            data = {'workflow_runs': runs, 'total_count': len(runs)}
        elif label == 'groups':
            data = {'value': [x for x in objects if '/providers/' not in x['id']]}
        elif label == 'resources':
            data = {'value': [x for x in objects if '/userAssignedIdentities/' in x['id'] and '/' not in x['id'].split('/userAssignedIdentities/')[1]
                              or '/accounts/' in x['id'] and '/' not in x['id'].split('/accounts/')[1]]}
        elif label == 'providers':
            data = {'value': [{'id': resources.root(self.config) + '/providers/' + k, 'namespace': k, 'registrationState': v}
                               for k, v in self.providers.items()]}
        elif label in ('roles', 'rgRoles', 'assignments', 'accountAssignments'):
            suffix = '/roleDefinitions/' if 'Roles' in label or label == 'roles' else '/roleAssignments/'
            data = {'value': [x for x in objects if suffix in x['id']]}
        elif label == 'deletedAccounts':
            data = {'value': self.deleted_accounts}
        elif label == 'accounts':
            data = {'value': [x for x in objects if '/accounts/' in x['id'] and '/' not in x['id'].split('/accounts/')[1]]}
        elif label == 'budgets':
            data = {'value': [x for x in objects if '/budgets/' in x['id']]}
        elif label:
            data = {'value': [x for x in objects if x['id'].startswith(path + '/') and '/' not in x['id'][len(path) + 1:]]}
        else:
            raise AssertionError('Unexpected synthetic GET')
        return subprocess.CompletedProcess(args, 0, json.dumps(data), '')


class SetupContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = configuration()
        self.config['azure']['configDir'] = self.temp.name
        self.cloud = Cloud(self.config)
        self.patch = mock.patch('subprocess.run', side_effect=self.cloud)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def plan(self, operation='apply', include_shared=False):
        return setup.plan_setup(self.config, operation, include_shared)

    def apply(self):
        plan = self.plan()
        self.assertEqual(plan['blockers'], [])
        return setup.execute(self.config, plan)

    def test_closed_configuration_and_independent_model_name(self):
        config = configuration()
        self.assertEqual(setup.setup_configuration(config)['modelName'], 'test-model')
        self.assertNotEqual(config['setup']['modelName'], config['model']['deploymentName'])
        for key, value in [('password', 'not-accepted'), ('modelMode', 'resize')]:
            candidate = copy.deepcopy(config)
            candidate['setup'][key] = value
            with self.assertRaises(setup.SetupError):
                setup.setup_configuration(candidate)

    def test_exact_resource_set_and_grants(self):
        specs = resources.resource_specs(configuration(), {})
        self.assertEqual(len([s for s in specs if s['kind'] == 'grant']), 5)
        self.assertEqual(len([s for s in specs if s['kind'] == 'role']), 2)
        self.assertFalse(any('managedClusters' in s['id'] for s in specs))
        self.assertEqual(len([s for s in specs if s['kind'] == 'fic']), 1)

    def test_apply_second_apply_cache_loss_and_default_destroy(self):
        self.assertEqual(self.cloud.writes, [])
        result = self.apply()
        self.assertEqual(len(result['completed']), 16)
        self.assertEqual(self.plan()['actions'], [])
        self.assertEqual(self.plan()['blockers'], [])
        self.cloud.writes.clear()
        setup.execute(self.config, self.plan())
        self.assertEqual(self.cloud.writes, [])
        destroy = self.plan('destroy')
        self.assertEqual(destroy['blockers'], [])
        self.assertEqual(destroy['actions'][0]['key'], 'ciFic')
        setup.execute(self.config, destroy)
        remaining = {s['key'] for s in resources.resource_specs(self.config, {}) if s['id'] in self.cloud.objects}
        self.assertEqual(remaining, {'anchor', 'modelRG', 'account', 'deployment', 'budget'})
        self.assertEqual(self.plan('destroy')['actions'], [])
        shared = self.plan('destroy', True)
        self.assertEqual(shared['blockers'], [])
        setup.execute(self.config, shared)
        self.assertEqual(self.cloud.objects, {})

    def test_cache_loss_profile_change_and_distinct_regions(self):
        self.config['model']['location'] = 'eastus2'
        self.apply()
        specs = {s['key']: s for s in resources.resource_specs(self.config, {})}
        for key in ('anchor', 'clusterRG', 'ci', 'model'):
            self.assertEqual(self.cloud.objects[specs[key]['id']]['location'], 'westus3')
        for key in ('account', 'modelRG'):
            item = self.cloud.objects[specs[key]['id']]
            self.assertEqual(item['location'], 'eastus2')
            self.assertEqual(item['tags']['ada-bootstrap-component'], 'shared-model')
            self.assertNotIn('ada-purpose', item['tags'])
        profile = Path(self.temp.name) / 'replacement-profile'
        profile.mkdir()
        self.config['azure']['configDir'] = str(profile)
        self.cloud.writes.clear()
        setup.execute(self.config, self.plan())
        self.assertEqual(self.cloud.writes, [])
        self.assertEqual(self.plan('destroy')['blockers'], [])

    def test_random_legacy_grants_are_references(self):
        self.apply()
        for item in self.cloud.objects.values():
            item.pop('tags', None)
        specs = resources.resource_specs(self.config, {})
        for index, spec in enumerate(s for s in specs if s['kind'] == 'grant'):
            item = self.cloud.objects.pop(spec['id'])
            item['id'] = spec['id'].rsplit('/', 1)[0] + '/99999999-9999-4999-8999-' + f'{index:012d}'
            self.cloud.objects[item['id']] = item
        self.cloud.writes.clear()
        self.assertEqual(self.plan()['actions'], [])
        self.assertEqual(self.plan()['blockers'], [])
        self.assertEqual(self.plan('destroy', True)['actions'], [])
        self.assertEqual(self.cloud.writes, [])

    def test_stale_and_tampered_approval_has_no_writes(self):
        plan = self.plan()
        plan['actions'][0]['id'] += '/unexpected'
        with self.assertRaises(setup.SetupError):
            setup.execute(self.config, plan)
        self.assertEqual(self.cloud.writes, [])
        plan = self.plan()
        self.config['model']['capacity'] += 1
        with self.assertRaises(setup.SetupError):
            setup.execute(self.config, plan)
        self.assertEqual(self.cloud.writes, [])

    def test_interruption_resumes_without_duplicate_children(self):
        for boundary in range(1, 17):
            with self.subTest(boundary=boundary):
                self.cloud.objects.clear()
                self.cloud.writes.clear()
                self.cloud.fail_write = boundary
                with self.assertRaises(setup.SetupError):
                    self.apply()
                self.cloud.fail_write = None
                self.apply()
                self.assertEqual(self.plan()['actions'], [])
                self.assertEqual(len(self.cloud.objects), 16)

    def test_reference_resources_are_not_adopted_or_deleted(self):
        self.apply()
        for item in self.cloud.objects.values():
            item.pop('tags', None)
        self.cloud.writes.clear()
        self.assertEqual(self.plan()['actions'], [])
        destroy = self.plan('destroy', True)
        self.assertEqual(destroy['actions'], [])
        self.assertEqual(len(destroy['retained']), 16)
        self.assertEqual(self.cloud.writes, [])

    def test_rogue_fic_grant_condition_and_config_drift_block(self):
        self.apply()
        snapshot = copy.deepcopy(self.cloud.objects)
        specs = {s['key']: s for s in resources.resource_specs(self.config, {})}
        for key, change in [('ciFic', lambda x: x['properties'].update(subject='unexpected')),
                            ('modelGrant', lambda x: x['properties'].update(condition='true')),
                            ('ci', lambda x: x['properties'].update(principalId='99999999-9999-4999-8999-999999999999'))]:
            with self.subTest(key=key):
                self.cloud.objects = copy.deepcopy(snapshot)
                change(self.cloud.objects[specs[key]['id']])
                self.assertTrue(self.plan()['blockers'])
        self.cloud.objects = snapshot
        self.config['model']['capacity'] += 1
        self.assertIn('resource-configuration-mismatch:deployment', self.plan()['blockers'])

    def test_private_plan_file_validation(self):
        path = Path(self.temp.name) / 'reviewed.json'
        path.write_text(json.dumps(self.plan()))
        path.chmod(0o600)
        self.assertEqual(setup.read_plan(path)['command'], 'apply')
        path.chmod(0o644)
        with self.assertRaises(setup.SetupError):
            setup.read_plan(path)
        path.chmod(0o600)
        link = Path(self.temp.name) / 'link'
        link.symlink_to(path)
        with self.assertRaises(setup.SetupError):
            setup.read_plan(link)
        path.write_text('{"version":1,"version":1}')
        with self.assertRaises(setup.SetupError):
            setup.read_plan(path)
        path.write_bytes(b' ' * (1024 * 1024 + 1))
        with self.assertRaises(setup.SetupError):
            setup.read_plan(path)

    def test_lock_deadline_and_sanitized_write_failure(self):
        with setup.operation_lock(self.config), self.assertRaisesRegex(setup.SetupError, 'locked'):
            setup.execute(self.config, self.plan())
        reader = setup.SetupTransport(self.config, deadline=time.monotonic() - 1)
        with self.assertRaisesRegex(setup.SetupError, 'deadline'):
            setup.plan_setup(self.config, 'apply', reader=reader)
        self.cloud.fail_write = 1
        with self.assertRaisesRegex(setup.SetupError, '^setup: write failed or ambiguous; re-plan required$'):
            self.apply()
        self.assertEqual(len(self.cloud.writes), 1)

    def test_transport_stdin_no_pii_in_argv_and_no_graph(self):
        self.apply()
        for args, kwargs in self.cloud.calls:
            self.assertNotIn(self.config['setup']['budget']['email'], ' '.join(args))
            self.assertNotIn('graph.microsoft.com', ' '.join(args))
            if '--body' in args:
                self.assertEqual(args[args.index('--body') + 1], '@/dev/stdin')
                self.assertIsInstance(kwargs['input'], str)
        encoded = json.dumps(self.plan())
        self.assertNotIn(self.config['setup']['budget']['email'], encoded)

    def test_quiescence_enabled_and_runs_block(self):
        self.apply()
        self.cloud.variables = {'AZURE_SUBSCRIPTION_ID': self.config['azure']['subscriptionID'],
                                'AKS_RESOURCE_GROUP': 'nightly', 'AKS_SCENARIO_ENABLED': 'true'}
        with self.assertRaisesRegex(setup.SetupError, 'scenario is enabled'):
            self.plan('destroy')
        self.cloud.variables['AKS_SCENARIO_ENABLED'] = 'false'
        for status in ('queued', 'in_progress', 'waiting', 'pending', 'requested'):
            self.cloud.runs = {('aks-cleanup.yml', status): [{'id': 1}]}
            with self.assertRaisesRegex(setup.SetupError, 'workflow is active'):
                self.plan('destroy')
        self.cloud.runs.clear()
        self.assertFalse(self.plan('destroy')['blockers'])

    def test_missing_parents_and_unregistered_providers(self):
        self.cloud.providers['Microsoft.ManagedIdentity'] = 'NotRegistered'
        plan = self.plan()
        self.assertEqual(plan['actions'][0]['action'], 'register')
        self.assertFalse(plan['blockers'])
        self.apply()
        self.assertEqual(self.plan()['actions'], [])

    def test_git_workflow_pagination_preserves_status_and_readonly(self):
        reader = setup.SetupReader(self.config)
        path = '/repos/example/agents/actions/workflows/aks-e2e.yml/runs?status=waiting&per_page=100&page=1'
        calls = []
        def get(service, url):
            reader._valid(service, url)
            calls.append(url)
            return {'total_count': 2, 'workflow_runs': [{'id': len(calls)}]}
        with mock.patch.object(reader, 'get', side_effect=get):
            self.assertEqual(len(reader.paginated('github', path, 'workflow_runs')), 2)
        self.assertEqual(parse_qs(urlsplit(calls[1]).query)['status'], ['waiting'])
        with self.assertRaises(inventory.InventoryError):
            reader.get('github', path.replace('status=waiting', 'status=completed'))
        self.assertFalse(hasattr(reader, 'mutate'))

    def test_deleted_accounts_empty_page_continuation(self):
        reader = setup.SetupReader(self.config)
        url = setup.setup_routes(self.config)['deletedAccounts']
        responses = iter([{'value': [], 'nextLink': url + '&$skiptoken=synthetic'},
                          {'value': [{'id': resources.root(self.config) + '/providers/Microsoft.CognitiveServices/deletedAccounts/example',
                                      'name': 'example-model'}]}])
        with mock.patch.object(reader, 'get', side_effect=lambda *_: next(responses)):
            self.assertEqual(len(reader.paginated('arm', url)), 1)
        self.cloud.deleted_accounts = [{'id': 'synthetic', 'name': 'example-model'}]
        self.assertIn('soft-deleted-account', self.plan()['blockers'])

    def test_ownership_collision_slots_and_unknown_children_block(self):
        self.apply()
        specs = {s['key']: s for s in resources.resource_specs(self.config, {})}
        anchor = self.cloud.objects[specs['anchor']['id']]
        anchor['tags']['unrelated'] = 'preserve-me'
        anchor['tags'][resources.slot('ciFic')] = 'wrong-name'
        self.assertIn('conflicting-anchor-slot', self.plan()['blockers'])
        anchor['tags'][resources.slot('ciFic')] = 'github-nightly-aks'
        unknown = specs['deployment']['id'].rsplit('/', 1)[0] + '/extra'
        self.cloud.objects[unknown] = {'id': unknown, 'name': 'extra', 'properties': {}}
        self.assertIn('unexpected-model-deployment', self.plan()['blockers'])
        self.assertIn('external-or-retained-child', self.plan('destroy', True)['blockers'])

    def test_merge_reservations_preserves_unrelated_tags_and_restarts(self):
        self.apply()
        specs = {s['key']: s for s in resources.resource_specs(self.config, {})}
        anchor = self.cloud.objects[specs['anchor']['id']]
        anchor['tags']['unrelated'] = 'preserve-me'
        del self.cloud.objects[specs['ciFic']['id']]
        del anchor['tags'][resources.slot('ciFic')]
        self.cloud.writes.clear()
        self.cloud.fail_write = 2
        with self.assertRaises(setup.SetupError):
            self.apply()
        self.assertEqual(self.cloud.writes[0][0], 'PATCH')
        self.assertEqual(anchor['tags']['unrelated'], 'preserve-me')
        self.assertEqual(anchor['tags'][resources.slot('ciFic')], 'github-nightly-aks')
        self.cloud.fail_write = None
        self.apply()
        self.assertEqual(self.plan()['actions'], [])

    def test_quiescence_changes_before_group_delete_stop(self):
        self.apply()
        plan = self.plan('destroy')
        self.cloud.writes.clear()
        def change(count, cloud):
            if count == 1:
                cloud.runs = {('aks-e2e.yml', 'waiting'): [{'id': 17}]}
        self.cloud.after_write = change
        with self.assertRaisesRegex(setup.SetupError, 'workflow is active'):
            setup.execute(self.config, plan)
        self.assertFalse(any(method == 'DELETE' and '/providers/' not in path for method, path, _ in self.cloud.writes))

    def test_all_mutation_flags_fail_before_reads_when_incompatible(self):
        for args in [ ['plan', '--execute'], ['check', '--include-shared'], ['apply', '--execute'],
                      ['apply', '--plan', 'reviewed.json'], ['apply', '--include-shared'] ]:
            with self.subTest(args=args), mock.patch('sys.stderr'), self.assertRaises(SystemExit):
                bootstrap.main(args + ['--config', 'not-read.json'])
        self.assertEqual(self.cloud.calls, [])

    def test_unknown_provider_and_reference_model_missing_block(self):
        self.config['setup']['registerProviders'] = []
        self.cloud.providers['Microsoft.CognitiveServices'] = 'NotRegistered'
        self.assertIn('provider-not-ready', self.plan()['blockers'])
        self.cloud.providers['Microsoft.CognitiveServices'] = 'Registered'
        self.config['setup']['modelMode'] = 'reference'
        self.assertIn('model-reference-missing', self.plan()['blockers'])

    def test_exact_role_actions_and_unsafe_definition_id(self):
        specs = {s['key']: s for s in resources.resource_specs(self.config, {})}
        self.assertEqual(specs['metadata']['body']['properties']['permissions'][0]['actions'], resources.METADATA)
        self.assertEqual(specs['federation']['body']['properties']['permissions'][0]['actions'], resources.FEDERATION)
        bad = copy.deepcopy(specs['metadata']['body'])
        bad['id'] = resources.root(self.config) + '/providers/Microsoft.Authorization/roleDefinitions/unsafe'
        self.cloud.objects[bad['id']] = bad
        with self.assertRaisesRegex(setup.SetupError, 'role definition target mismatch'):
            self.plan()


    def test_reserved_role_never_owns_same_named_foreign_guid(self):
        self.cloud.fail_write = 2
        with self.assertRaisesRegex(setup.SetupError, 'write failed or ambiguous'):
            self.apply()
        self.cloud.fail_write = None
        spec = next(s for s in resources.resource_specs(self.config, {}) if s['key'] == 'metadata')
        target = spec['id'].rsplit('/', 1)[0] + '/99999999-9999-4999-8999-999999999999'
        self.cloud.objects[target] = dict(copy.deepcopy(spec['body']), id=target, name=target.rsplit('/', 1)[-1])
        plan = self.plan('destroy')
        self.assertIn('reserved-target-conflict', plan['blockers'])
        self.assertFalse(any(a['id'] == target and a['action'] == 'delete' for a in plan['actions']))

    def test_human_configuration_is_not_azure_ownership(self):
        self.apply()
        self.config['human']['apiName'] = 'another-api'
        self.assertEqual(self.plan()['blockers'], [])
        self.assertEqual(self.plan()['actions'], [])
        self.assertEqual(self.plan('destroy', True)['blockers'], [])

    def test_expired_budget_blocks_apply_not_owned_teardown(self):
        self.apply()
        expired = datetime.datetime.fromisoformat(self.config['setup']['budget']['endDate']).replace(tzinfo=datetime.timezone.utc)
        writes = len(self.cloud.writes)
        with mock.patch.object(setup.datetime, 'datetime') as clock:
            clock.now.return_value = expired
            self.assertIn('budget-period-not-active', self.plan()['blockers'])
            self.assertEqual(len(self.cloud.writes), writes)
            plan = self.plan('destroy', True)
            self.assertEqual(plan['blockers'], [])
            setup.execute(self.config, plan)
        self.assertEqual(self.cloud.objects, {})

    def test_missing_mapping_or_scenario_flag_cannot_prove_quiescence(self):
        self.cloud.variables = {'AKS_SCENARIO_ENABLED': 'true'}
        with self.assertRaisesRegex(setup.SetupError, 'scenario'):
            setup.quiescence(self.config, setup.SetupReader(self.config))
        self.cloud.variables = {}
        with self.assertRaisesRegex(setup.SetupError, 'scenario'):
            setup.quiescence(self.config, setup.SetupReader(self.config))
        self.cloud.variables = {'AKS_SCENARIO_ENABLED': 'false'}
        self.assertTrue(setup.quiescence(self.config, setup.SetupReader(self.config))['targeted'])

    def test_new_grants_require_owned_principal_identity(self):
        self.apply()
        specs = {s['key']: s for s in resources.resource_specs(self.config, {})}
        self.cloud.objects[specs['ci']['id']]['tags'] = {}
        del self.cloud.objects[specs['aksContributor']['id']]
        self.assertIn('grant-principal-is-reference', self.plan()['blockers'])

    def test_wire_body_must_match_approved_digest(self):
        original = setup.resolved_body
        def corrupted(spec, state, specs):
            body = original(spec, state, specs)
            if spec['key'] == 'deployment':
                body['sku']['capacity'] += 1
            return body
        with mock.patch.object(setup, 'resolved_body', side_effect=corrupted), self.assertRaisesRegex(setup.SetupError, 'request body differs from approval'):
            self.apply()
        self.assertFalse(any('/deployments/' in path for _, path, _ in self.cloud.writes))

    def test_soft_deleted_account_is_not_a_destroy_blocker(self):
        self.apply()
        self.cloud.deleted_accounts = [{'id': '/deleted/test-account', 'name': self.config['model']['accountName']}]
        self.assertNotIn('soft-deleted-account', self.plan('destroy', True)['blockers'])

    def test_apply_fits_deadline_at_realistic_cli_latency(self):
        ticks = [1000.0]
        def timed_wire(args, **kwargs):
            ticks[0] += 1.5
            return self.cloud(args, **kwargs)
        with mock.patch('subprocess.run', side_effect=timed_wire), mock.patch.object(setup.time, 'monotonic', side_effect=lambda: ticks[0]):
            self.apply()
        self.assertLess(ticks[0] - 1000, 600)

    def test_unrelated_resources_and_spend_do_not_invalidate_plan(self):
        base = resources.root(self.config)
        target = base + '/resourceGroups/unrelated'
        self.cloud.objects[target] = {'id': target, 'name': 'unrelated', 'location': 'westus3', 'tags': {}}
        changes = [0]
        def changing_wire(args, **kwargs):
            changes[0] += 1
            self.cloud.objects[target]['tags']['noise'] = str(changes[0])
            for item in self.cloud.objects.values():
                if '/budgets/' in item['id']:
                    item['properties']['currentSpend'] = {'unit': 'USD', 'amount': changes[0]}
            return self.cloud(args, **kwargs)
        with mock.patch('subprocess.run', side_effect=changing_wire):
            self.apply()
        self.assertGreater(len(self.cloud.writes), 0)


if __name__ == '__main__':
    unittest.main()
