import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ncfta_curate import build_dataset, export_dataset, load_rules, validate

RULES=Path(__file__).with_name('ncfta_mapping_rules.json')


class CurateTests(unittest.TestCase):
    def setUp(self):
        self.rules=load_rules(RULES)
        self.e=dict(id='1',uuid='event-1',date='2026-09-01',distribution='4',sharing_group_id='6',Attribute=[])

    def attr(self,typ,value,category,comment='',**extra):
        a=dict(id=str(len(self.e['Attribute'])+1),uuid='a-'+str(len(self.e['Attribute'])+1),event_id='1',type=typ,value=value,category=category,comment=comment,distribution='5',sharing_group_id='0',**extra)
        self.e['Attribute'].append(a)
        return a

    def build(self):return build_dataset({'response':[{'Event':self.e}]},self.rules)

    def test_label_normalization_category_conflict_and_unknown_label(self):
        self.attr('other','Example Bank','Financial fraud','  BANK  ')
        self.attr('other','Example Bank','Person','Bank')
        self.attr('other','Something','Financial fraud','Bank Owner')
        rows=self.build()['fields']
        self.assertEqual(rows[0]['final_value'],'Example Bank')
        self.assertEqual(rows[1]['mapping_status'],'category_conflict')
        self.assertIsNone(rows[1]['final_value'])
        self.assertEqual(rows[2]['mapping_status'],'unmapped')

    def test_partial_ssn_is_not_full_or_final(self):
        self.attr('other','0012','Person','SSN')
        d=self.build(); r=d['fields'][0]
        self.assertEqual((r['field_name'],r['normalized_value'],r['validation_status']),('ssn_partial','0012','partial'))
        self.assertIsNone(r['final_value']);self.assertEqual(d['analyst_events'][0]['fields']['ssn'],[])

    def test_date_ambiguity_and_routing_validation(self):
        self.assertEqual(validate('date','01/02/2000')[1],'needs_review')
        self.assertEqual(validate('date','01/02/2000','DMY')[0],'2000-02-01')
        self.assertEqual(validate('date','01/02/2000','MDY')[0],'2000-01-02')
        self.assertEqual(validate('date','31/02/2000')[1],'needs_review')
        self.assertEqual(validate('routing','021000021')[1],'format_pass')
        self.assertEqual(validate('routing','021000022')[1],'needs_review')
        self.assertIsNone(validate('routing','21000021')[0])
        self.assertEqual(validate('datetime','2026-09-01')[1],'needs_review')
        self.assertEqual(validate('date','2000-01-02 00:00:00')[0],'2000-01-02')
        self.assertEqual(validate('amount','$1,234.56')[0],'$1234.56')
        self.assertEqual(validate('amount','$12,34.56')[1],'needs_review')
        self.assertEqual(validate('decimal','1,234')[0],'1234')

    def test_narrative_candidates_require_review_with_exact_offsets(self):
        narrative='Narrative\nMerchant Name: Demo Shop; other text\nPAN: 4111 1111 1111 1111\nUnlabelled 5555555555554444'
        self.attr('comment',narrative,'Other')
        d=self.build(); candidates=[r for r in d['fields'] if r['mapping_status']=='candidate']
        self.assertEqual(len(candidates),2)
        for r in candidates:
            self.assertIsNone(r['final_value']);self.assertEqual(r['review_status'],'required')
            self.assertIn(narrative[r['evidence_start']:r['evidence_end']],['Demo Shop','4111 1111 1111 1111'])
        self.assertEqual(d['analyst_events'][0]['fields']['card_pan'],[])
        self.assertEqual(d['analyst_events'][0]['fields']['merchant_name'],[])

    def test_no_bank_account_pairings_and_leading_zeros_preserved(self):
        for v in ['Bank A','Bank B']:self.attr('other',v,'Financial fraud','Bank')
        for v in ['001234','005678']:self.attr('bank-account-nr',v,'Financial fraud')
        a=self.build()['analyst_events'][0]
        self.assertEqual([r['value'] for r in a['fields']['bank_account_number']],['001234','005678'])
        self.assertNotIn('bank_account_pairs',a)

    def test_deleted_and_broken_links_never_final(self):
        a=self.attr('other','Bank A','Financial fraud','Bank',deleted=True)
        b=self.attr('other','Bank B','Financial fraud','Bank');b['event_id']='2'
        self.assertTrue(all(r['final_value'] is None for r in self.build()['fields']))

    def test_object_permissions_and_duplicate_uuid(self):
        a=self.attr('other','Bank A','Financial fraud','Bank');self.e['Attribute']=[]
        self.e['Object']=[dict(uuid='obj-1',name='example',distribution='4',sharing_group_id='8',Attribute=[a])]
        r=self.build()['fields'][0]
        self.assertEqual((r['object_uuid'],r['object_distribution'],r['object_sharing_group_id']),('obj-1','4','8'))
        self.e['Attribute']=[a]
        with self.assertRaisesRegex(ValueError,'duplicate attribute'):self.build()

    def test_exports_protect_formulas_exact_json_no_overwrite_and_cleanup(self):
        self.attr('comment','=1+1','Other')
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            p=Path(temp);src=p/'source.json';src.write_text(json.dumps({'response':[{'Event':self.e}]}))
            out=p/'export';export_dataset(src,out,RULES)
            self.assertIn("'=1+1",(out/'fields.csv').read_text(encoding='utf-8-sig'))
            self.assertEqual(json.loads((out/'fields.json').read_text())[0]['source_value'],'=1+1')
            before=(out/'manifest.json').read_bytes()
            with self.assertRaises(FileExistsError):export_dataset(src,out,RULES)
            self.assertEqual((out/'manifest.json').read_bytes(),before)
            with patch('ncfta_curate.write_csv',side_effect=OSError('simulated failure')):
                with self.assertRaises(OSError):export_dataset(src,p/'failed',RULES)
            self.assertFalse((p/'failed').exists());self.assertEqual(list(p.glob('.ncfta-curate-*')),[])

    def test_rule_registry_rejects_duplicates(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            rules=copy.deepcopy(self.rules);rules['rules'].append(copy.deepcopy(rules['rules'][0]));rules['rules'][-1]['id']='different'
            path=Path(temp)/'rules.json';path.write_text(json.dumps(rules))
            with self.assertRaisesRegex(ValueError,'Duplicate normalized'):load_rules(path)


if __name__=='__main__':unittest.main()
