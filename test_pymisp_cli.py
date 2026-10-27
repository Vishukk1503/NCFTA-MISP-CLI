"""Offline regression tests: no credentials or live server required."""
import importlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, PropertyMock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import requests
from pymisp import PyMISP
from pymisp.exceptions import PyMISPError
import ncfta_client
import ncfta_extract_sample
import ncfta_list_groups


def response(payload, status=200):
    r = requests.Response()
    r.status_code = status
    r._content = json.dumps(payload).encode()
    r.raw = io.BytesIO(r._content)
    r.headers['Content-Type'] = 'application/json'
    return r


class PyMISPTests(unittest.TestCase):
    def setUp(self):
        # Only mock startup lookups; searches/group parsing use real PyMISP code.
        for name, value in [('recommended_pymisp_version', {'version': '2.5.34.4'}),
                            ('misp_instance_version', {'version': '2.5.34'}),
                            ('describe_types_remote', {'categories': [], 'types': [],
                             'category_type_mappings': {}, 'sane_defaults': {}})]:
            p = patch.object(PyMISP, name, new_callable=PropertyMock, return_value=value)
            p.start(); self.addCleanup(p.stop)
        p = patch.object(PyMISP, 'get_user', return_value=(None, None, []))
        p.start(); self.addCleanup(p.stop)

    @patch.object(requests.adapters.HTTPAdapter, 'send')
    def test_real_pymisp_group_call_and_tls(self, send):
        send.return_value = response({'response': [{'SharingGroup': {'id': '6', 'name': 'Cyfin'}}]})
        with ncfta_client.connect('https://misp.example', 'test-key', 25) as client:
            groups = ncfta_list_groups.parse_groups(client.sharing_groups(pythonify=False))
        self.assertEqual(groups[0]['id'], '6')
        request = send.call_args.args[0]
        self.assertEqual(request.method, 'GET')
        self.assertEqual(request.url, 'https://misp.example/sharingGroups/index')
        self.assertIs(send.call_args.kwargs['verify'], True)
        self.assertEqual(send.call_args.kwargs['timeout'], 25)

    @patch.object(requests.adapters.HTTPAdapter, 'send')
    def test_real_pymisp_event_search_payload_and_response(self, send):
        event = {'Event': {'id': '1', 'sharing_group_id': '6', 'date': '2026-09-01', 'Attribute': []}}
        send.return_value = response({'response': [event]})
        with ncfta_client.connect('https://misp.example', 'test-key', 25, Path('ca.pem')) as client:
            result = client.search(controller='events', sharinggroup=[6], date_from='2026-09-01',
                                   date_to='2026-09-01', page=1, limit=3,
                                   metadata=False, with_attachments=False, pythonify=False)
        self.assertEqual(ncfta_extract_sample.extract_events(result, 6, 3), [event])
        request = send.call_args.args[0]
        body = json.loads(request.body)
        self.assertEqual(body['sharinggroup'], [6])
        self.assertEqual(body['from'], '2026-09-01')
        self.assertEqual(body['to'], '2026-09-01')
        self.assertFalse(body['withAttachments'])
        self.assertEqual(request.url, 'https://misp.example/events/restSearch')
        self.assertEqual(send.call_args.kwargs['verify'], 'ca.pem')

    @patch.object(requests.adapters.HTTPAdapter, 'send')
    def test_redirects_and_http_errors_are_refused(self, send):
        for code in (302, 401, 403, 500):
            send.reset_mock(); send.return_value = response({}, code)
            with self.subTest(code=code), self.assertRaises(ncfta_client.NCFTAClientError):
                with ncfta_client.connect('https://misp.example', 'test-key', 25) as client:
                    client.sharing_groups()
            self.assertEqual(send.call_count, 1)

    @patch.object(requests.adapters.HTTPAdapter, 'send')
    def test_other_origins_and_write_routes_never_sent(self, send):
        adapter = ncfta_client.ReadOnlyAdapter(('https', 'misp.example'))
        for url, method in [('https://other.example/events/restSearch', 'POST'),
                            ('https://misp.example/events/add', 'POST')]:
            request = requests.Request(method, url).prepare()
            with self.assertRaises(ncfta_client.NCFTAClientError):
                adapter.send(request, verify=True)
        send.assert_not_called()

    @patch.object(requests.adapters.HTTPAdapter, 'send')
    def test_cli_pagination_json_and_csv_compatibility(self, send):
        event = {'Event': {'id': '1', 'sharing_group_id': '6', 'date': '2026-09-01',
                           'Attribute': [{'id': '10', 'type': 'text', 'value': 'example'}]}}
        send.side_effect = [response({'response': [event]}), response({'response': []})]
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as td:
            args = ['script', '--url', 'https://misp.example', '--group', '6',
                    '--from-date', '2026-09-01', '--to-date', '2026-09-01',
                    '--all-pages', '--output-dir', td]
            with patch.object(sys, 'argv', args), patch.object(sys.stdin, 'isatty', return_value=True), \
                 patch.object(ncfta_extract_sample.getpass, 'getpass', return_value='test-key'):
                self.assertEqual(ncfta_extract_sample.main(), 0)
            saved = next(Path(td).glob('*.json'))
            doc = json.loads(saved.read_text())
            self.assertEqual(doc['response'], [event])
            self.assertEqual(doc['event_count'], 1)
            self.assertEqual([json.loads(c.args[0].body)['page'] for c in send.call_args_list], [1, 2])
            converter = importlib.import_module('ncfta_json_to_csv')
            self.assertEqual(converter.export_csv(saved, Path(td))[2:], (1, 1))

    def test_bad_group_and_dates_still_rejected(self):
        from datetime import date
        for event in [{'id': '1', 'sharing_group_id': '8', 'date': '2026-09-01'},
                      {'id': '1', 'sharing_group_id': '6', 'date': '2026-08-31'}]:
            with self.assertRaises(ValueError):
                ncfta_extract_sample.extract_events([{'Event': event}], 6, 3,
                                                   date(2026, 9, 1), date(2026, 9, 1))

    @patch.object(ncfta_client, 'PyMISP', side_effect=PyMISPError('sensitive-test-key'))
    def test_constructor_errors_do_not_disclose_credentials(self, client):
        with self.assertRaises(ncfta_client.NCFTAClientError) as ctx:
            with ncfta_client.connect('https://misp.example', 'sensitive-test-key', 25):
                pass
        self.assertNotIn('sensitive-test-key', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()

