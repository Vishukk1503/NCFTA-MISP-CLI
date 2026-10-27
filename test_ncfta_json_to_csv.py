import csv
import json
from pathlib import Path
import tempfile
import unittest

from ncfta_json_to_csv import export_csv, new_output_files


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.source = self.folder / 'sample.json'
        self.event = {'id': '1', 'sharing_group_id': '6', 'Attribute': [
            {'id': '10', 'type': 'bank-account-nr', 'value': '001234',
             'distribution': '4', 'sharing_group_id': '8'},
            {'id': '11', 'type': 'comment', 'value': '=1+1',
             'distribution': '5', 'sharing_group_id': '0'}],
            'Object': [{'id': '20', 'name': 'example', 'Attribute': [
                {'id': '12', 'type': 'text', 'value': 'test',
                 'distribution': '4', 'sharing_group_id': '7'}]}]}
        self.source.write_text(json.dumps({'response': [{'Event': self.event}]}))

    def test_sharing_rules_and_object_context_preserved(self):
        ep, ap, ec, ac = export_csv(self.source, self.folder)
        self.assertEqual((ec, ac), (1, 3))
        with ap.open(encoding='utf-8-sig', newline='') as f:
            rows = list(csv.DictReader(f))
        self.assertEqual([r['sharing_group_id'] for r in rows], ['6'] * 3)
        self.assertEqual([r['attribute_sharing_group_id'] for r in rows], ['8', '0', '7'])
        self.assertEqual([r['attribute_distribution'] for r in rows], ['4', '5', '4'])
        self.assertEqual(rows[0]['attribute_value'], '001234')
        self.assertEqual(rows[1]['attribute_value'], "'=1+1")
        self.assertEqual(rows[2]['object_id'], '20')

    def test_rerun_keeps_both_existing_outputs(self):
        ep, ap, _, _ = export_csv(self.source, self.folder)
        original = (ep.read_bytes(), ap.read_bytes())
        with self.assertRaises(FileExistsError):
            export_csv(self.source, self.folder)
        self.assertEqual((ep.read_bytes(), ap.read_bytes()), original)

    def test_either_existing_output_blocks_pair_creation(self):
        for suffix, other in [('events', 'attributes'), ('attributes', 'events')]:
            with self.subTest(suffix=suffix):
                folder = self.folder / suffix
                folder.mkdir()
                existing = folder / f'sample_{suffix}.csv'
                existing.write_text('KEEP')
                with self.assertRaises(FileExistsError):
                    export_csv(self.source, folder)
                self.assertEqual(existing.read_text(), 'KEEP')
                self.assertFalse((folder / f'sample_{other}.csv').exists())

    def test_failed_write_cleans_up_new_outputs(self):
        ep, ap = self.folder / 'new_events.csv', self.folder / 'new_attributes.csv'
        with self.assertRaises(RuntimeError):
            with new_output_files(ep, ap) as (ef, af):
                ef.write('partial')
                raise RuntimeError('simulated failure')
        self.assertFalse(ep.exists())
        self.assertFalse(ap.exists())


if __name__ == '__main__':
    unittest.main()

