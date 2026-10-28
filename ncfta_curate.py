"""Offline NCFTA final-field export with editable rules, provenance and review queue.

Uses only the Python standard library. Original exports are never modified.
"""
import argparse
from collections import Counter
from datetime import date, datetime, timezone
from decimal import Decimal
import csv
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import urlsplit

from ncfta_json_to_csv import events_from_document, event_row, attribute_row, cell, EVENT_FIELDS, ATTRIBUTE_FIELDS


def text(value):
    return '' if value is None else str(value)


def label(value):
    return ' '.join(text(value).split()).casefold()


def luhn(value):
    nums=[int(c) for c in value][::-1]
    return sum(n if i%2==0 else (n*2-9 if n*2>9 else n*2) for i,n in enumerate(nums))%10==0


def validate(kind, value, date_order=None):
    """Return normalized candidate, validation status and reason. Never repair IDs."""
    v=text(value).strip()
    if not v:
        return None,'missing','empty_value'
    if v.casefold() in {'n/a','na','unknown','none','null','not provided','-','?'}:
        return None,'needs_review','placeholder_value'
    if kind=='text':
        return v,'not_checked','source_reported_text_not_independently_verified'
    if kind=='ssn':
        digits=re.sub(r'[- ]','',v)
        if re.fullmatch(r'[0-9]{1,4}',digits):
            return digits,'partial','short_ssn_label_value_requires_review'
        if re.fullmatch(r'[0-9]{9}',digits) and digits[:3] not in ('000','666') and int(digits[:3])<900 and digits[3:5]!='00' and digits[5:]!='0000':
            return digits,'format_pass','ssn_shape_only_not_identity_validation'
        return None,'needs_review','invalid_or_masked_ssn'
    if kind=='routing':
        if not re.fullmatch(r'[0-9]{9}',v):
            return None,'needs_review','routing_requires_nine_digits_no_auto_padding'
        if v=='000000000' or sum(int(v[i])*[3,7,1][i%3] for i in range(9))%10:
            return None,'needs_review','routing_checksum_failed'
        return v,'format_pass','routing_checksum_only_not_bank_verification'
    if kind=='account':
        if re.fullmatch(r'[0-9]+',v):return v,'format_pass','digits_only_no_ownership_or_account_verification'
        return None,'needs_review','non_digit_account_value_requires_review'
    if kind in ('pan','bin'):
        digits=re.sub(r'[ -]','',v)
        if kind=='pan' and re.fullmatch(r'[0-9]{13,19}',digits) and len(set(digits))>1 and luhn(digits):
            return digits,'format_pass','pan_length_and_luhn_only'
        if kind=='bin' and re.fullmatch(r'(?:[0-9]{6}|[0-9]{8})',digits):return digits,'format_pass','explicit_bin_label_and_shape_only'
        return None,'needs_review','invalid_'+kind+'_format_or_checksum'
    if kind in ('date','datetime'):
        try:
            if kind=='datetime':
                parsed=datetime.fromisoformat(v.replace('Z','+00:00'))
                if not re.search(r'[T ][0-9]{2}:[0-9]{2}',v):raise ValueError()
                return parsed.isoformat(),'format_pass','timezone_preserved' if parsed.tzinfo else 'timezone_unspecified'
            if re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}',v):
                return date.fromisoformat(v).isoformat(),'format_pass','iso_calendar_date'
            if re.match(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ]',v):
                parsed=datetime.fromisoformat(v.replace('Z','+00:00'))
                return parsed.date().isoformat(),'format_pass','calendar_date_from_source_iso_datetime_no_timezone_shift'
            m=re.fullmatch(r'([0-9]{1,2})/([0-9]{1,2})/([0-9]{4})',v)
            if m:
                a,b,y=map(int,m.groups())
                order=date_order or ('DMY' if a>12 else 'MDY' if b>12 else None)
                if order is None:return None,'needs_review','ambiguous_slash_date_set_date_order_after_confirmation'
                mo,day=(a,b) if order=='MDY' else (b,a)
                return date(y,mo,day).isoformat(),'format_pass','slash_date_'+order
        except ValueError:
            pass
        return None,'needs_review','unsupported_or_invalid_'+kind
    if kind in ('decimal','amount'):
        m=re.fullmatch(r'(?P<symbol>[$£€])?\s*(?P<number>-?(?:[0-9]+|[0-9]{1,3}(?:,[0-9]{3})+)(?:\.[0-9]+)?)',v)
        if m and (kind=='amount' or not m['symbol']):
            return (m['symbol'] or '')+str(Decimal(m['number'].replace(',',''))),'format_pass','dot_decimal_comma_grouping_currency_symbol_preserved_no_currency_code_inferred'
        return None,'needs_review','ambiguous_numeric_format_or_units'
    if kind=='ip':
        try:return str(ipaddress.ip_address(v)),'format_pass','ip_syntax_only'
        except ValueError:return None,'needs_review','invalid_ip'
    if kind=='email':
        if re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',v):return v,'format_pass','email_shape_only'
        return None,'needs_review','invalid_email_shape'
    if kind=='phone':
        cleaned=re.sub(r'[\s().-]','',v)
        if re.fullmatch(r'\+?[0-9]{7,15}',cleaned):return cleaned,'format_pass','phone_shape_only_country_code_not_inferred'
        return None,'needs_review','invalid_phone_shape'
    if kind=='swift':
        if re.fullmatch(r'[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?',v.upper()):return v.upper(),'format_pass','swift_shape_only'
        return None,'needs_review','invalid_swift_shape'
    if kind=='domain':
        if re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}',v):return v.lower(),'format_pass','domain_shape_only'
        return None,'needs_review','unsupported_or_invalid_domain'
    if kind=='url':
        try:
            parts=urlsplit(v)
            if parts.scheme in ('http','https') and parts.hostname and not re.search(r'\s',v):return v,'format_pass','http_url_shape_only'
        except ValueError:pass
        return None,'needs_review','unsupported_or_invalid_url'
    raise ValueError('Unsupported validator: '+kind)


VALIDATORS={'text','ssn','routing','account','pan','bin','date','datetime','decimal','amount','ip','email','phone','swift','domain','url'}


def load_rules(path):
    rules=json.loads(Path(path).read_text(encoding='utf-8-sig'))
    if not rules.get('rule_version') or not isinstance(rules.get('rules'),list):raise ValueError('Rules need rule_version and rules list')
    ids=set(); keys=set()
    for r in rules['rules']+rules.get('narrative_rules',[]):
        if not r.get('id') or r['id'] in ids:raise ValueError('Missing or duplicate rule ID')
        ids.add(r['id'])
        if not r.get('field') or r.get('validator') not in VALIDATORS:raise ValueError('Invalid rule field/validator')
    for r in rules['rules']:
        key=(r['source_type'],None if r.get('source_label') is None else label(r['source_label']))
        if key in keys:raise ValueError('Duplicate normalized mapping rule')
        keys.add(key)
        if not r.get('expected_categories'):raise ValueError('Mapping rule must declare expected_categories')
    for r in rules.get('narrative_rules',[]):
        if not r.get('labels') or not all(isinstance(v,str) and v.strip() for v in r['labels']):raise ValueError('Narrative labels must be nonempty strings')
    return rules


def classify(attr,rules):
    matches=[r for r in rules['rules'] if r['source_type']==attr.get('type') and (r.get('source_label') is None or label(r['source_label'])==label(attr.get('comment')))]
    exact=[r for r in matches if r.get('source_label') is not None]
    return (exact or matches or [None])[0]


def build_dataset(doc,rules,date_order=None):
    events=list(events_from_document(doc)); fields=[]; attr_rows=[]; event_rows=[]; analyst=[]; seen_events=set(); seen_attrs=set()
    findings=Counter(); fallback=doc.get('sharing_group_id','') if isinstance(doc,dict) else ''
    wanted=sorted({r['field'] for r in rules['rules']}|{'ssn_partial'})
    for e in events:
        if not e.get('uuid') or e['uuid'] in seen_events:raise ValueError('Missing or duplicate event UUID')
        seen_events.add(e['uuid']); base=event_row(e,fallback); event_rows.append(base)
        source_attrs=[(a,{}) for a in e.get('Attribute') or []]
        source_attrs += [(a,o) for o in e.get('Object') or [] for a in o.get('Attribute') or []]
        accepted={k:[] for k in wanted}; event_fields=[]
        if 'attribute_count' in e and int(e['attribute_count'])!=len(source_attrs):findings['event_attribute_count_mismatch']+=1
        for a,obj in source_attrs:
            if not a.get('uuid') or a['uuid'] in seen_attrs:raise ValueError('Missing or duplicate attribute UUID')
            seen_attrs.add(a['uuid']); ar=attribute_row({k:v for k,v in base.items() if k!='event_attribute_count'},a,obj)
            ar.update(deleted=a.get('deleted'),disable_correlation=a.get('disable_correlation'))
            attr_rows.append(ar)
            rule=classify(a,rules); raw=text(a.get('value')); normalized=None
            status='not_checked'; reason='unknown_type_or_comment_label'; field='unmapped'; area='Unmapped'
            mapping_status='unmapped'; rid=''; method='unmapped'
            if rule:
                rid=rule['id']; field=rule['field']; area=rule['business_area']; method='source_label' if rule.get('source_label') is not None else 'source_type'
                normalized,status,reason=validate(rule['validator'],raw,date_order)
                mapping_status='mapped' if label(a.get('category')) in {label(c) for c in rule['expected_categories']} else 'category_conflict'
                if field=='ssn' and status=='partial':field='ssn_partial'
            blocked=[]
            if mapping_status!='mapped':blocked.append(mapping_status)
            if status in ('missing','needs_review','partial'):blocked.append(reason)
            if text(a.get('event_id'))!=text(e['id']):blocked.append('attribute_event_link_mismatch')
            if a.get('deleted') in (True,1,'1'):blocked.append('source_attribute_deleted')
            if obj and obj.get('distribution') is not None:
                # Retain object permissions for downstream authorization; no permission widening here.
                ar['object_distribution']=obj.get('distribution'); ar['object_sharing_group_id']=obj.get('sharing_group_id')
            final=normalized if not blocked else None
            row=dict(event_id=text(e['id']),event_uuid=e['uuid'],source_attribute_uuid=a['uuid'],source_attribute_id=text(a.get('id')),
                     object_uuid=obj.get('uuid'),object_name=obj.get('name'),object_relation=a.get('object_relation'),
                     object_distribution=obj.get('distribution'),object_sharing_group_id=obj.get('sharing_group_id'),
                     event_date=e.get('date'),event_distribution=e.get('distribution'),event_sharing_group_id=e.get('sharing_group_id'),
                     attribute_distribution=a.get('distribution'),attribute_sharing_group_id=a.get('sharing_group_id'),
                     source_type=a.get('type'),source_category=a.get('category'),source_comment=a.get('comment'),source_value=raw,
                     field_name=field,business_area=area,normalized_value=normalized,final_value=final,
                     extraction_method=method,rule_id=rid,rule_version=rules['rule_version'],mapping_status=mapping_status,
                     validation_status=status,validation_reason=reason,review_status='required' if blocked else 'not_required',
                     review_reason='; '.join(blocked),evidence_start=0,evidence_end=len(raw))
            fields.append(row);event_fields.append(row)
            if final is not None:accepted.setdefault(field,[]).append(dict(value=final,source_attribute_uuid=a['uuid'],rule_id=rid))
            for why in blocked:findings[why]+=1
            # Search only narrative attributes. Anchored labels avoid general numeric guessing.
            if a.get('type') in ('comment','text') and label(a.get('comment'))!='reported by' and a.get('deleted') not in (True,1,'1'):
                for nr in rules.get('narrative_rules',[]):
                    aliases='|'.join(re.escape(t) for t in sorted(nr['labels'],key=len,reverse=True))
                    pattern=re.compile(r'^[ \t]*(?:'+aliases+r')[ \t]*[:=][ \t]*(?P<value>[^\r\n;]+)',re.I|re.M)
                    for match in pattern.finditer(raw):
                        val=match.group('value'); norm,vs,vr=validate(nr['validator'],val,date_order)
                        candidate={**row,'field_name':'ssn_partial' if nr['field']=='ssn' and vs=='partial' else nr['field'],
                                   'business_area':nr['business_area'],'normalized_value':norm,'final_value':None,
                                   'extraction_method':'narrative_label_candidate','rule_id':nr['id'],'mapping_status':'candidate',
                                   'validation_status':vs,'validation_reason':vr,'review_status':'required',
                                   'review_reason':'narrative_extraction_requires_human_review','evidence_start':match.start('value'),'evidence_end':match.end('value')}
                        fields.append(candidate);event_fields.append(candidate);findings['narrative_extraction_requires_human_review']+=1
        ac=sum(len(v) for v in accepted.values()); needs=sum(r['review_status']=='required' for r in event_fields)
        analyst.append(dict(event_id=text(e['id']),event_uuid=e['uuid'],event_date=e.get('date'),event_info=e.get('info'),
                            event_distribution=e.get('distribution'),event_sharing_group_id=e.get('sharing_group_id'),
                            source_attribute_count=len(source_attrs),final_field_count=ac,review_row_count=needs,
                            fields=accepted,relationship_policy='Values are event-associated; no person/account/bank pairings inferred.'))
    quality=dict(event_count=len(events),source_attribute_count=len(attr_rows),field_row_count=len(fields),
                 final_field_count=sum(r['final_value'] is not None for r in fields),review_row_count=sum(r['review_status']=='required' for r in fields),
                 source_mapping_status_counts=dict(Counter(r['mapping_status'] for r in fields if r['extraction_method']!='narrative_label_candidate')),
                 validation_status_counts=dict(Counter(r['validation_status'] for r in fields)),review_reasons=dict(findings),
                 field_counts=dict(Counter(r['field_name'] for r in fields)),
                 limitations=['Rule coverage is not semantic accuracy. No precision/recall benchmark has been established.',
                              'Narrative search only finds configured labels at line starts. No claim of exhaustive extraction.',
                              'Format checks do not verify source claims, ownership, identity, bank existence, or entitlement.',
                              'Analyst event aggregation retains attribute-grain permissions in field detail; it is not an access-control engine.'])
    return dict(events=event_rows,attributes=attr_rows,fields=fields,analyst_events=analyst,quality=quality,field_names=wanted)


def write_csv(path,rows,headers):
    with path.open('x',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=headers);writer.writeheader()
        for row in rows:writer.writerow({k:cell(row.get(k)) for k in headers})


FIELD_HEADERS=['event_id','event_uuid','field_name','final_value','normalized_value','review_status','review_reason','validation_status','validation_reason','mapping_status','extraction_method','rule_id','rule_version','business_area','source_attribute_uuid','source_attribute_id','source_type','source_category','source_comment','source_value','evidence_start','evidence_end','event_date','event_distribution','event_sharing_group_id','attribute_distribution','attribute_sharing_group_id','object_uuid','object_name','object_relation','object_distribution','object_sharing_group_id']


def export_dataset(source,output_dir,rules_path,date_order=None):
    """Publish one new directory only after all exports succeed; refuse overwrites."""
    source=Path(source);output_dir=Path(output_dir);rules_path=Path(rules_path)
    if output_dir.exists():raise FileExistsError('Output directory already exists; choose a new --output-dir')
    source_bytes=source.read_bytes(); doc=json.loads(source_bytes.decode('utf-8-sig')); rules=load_rules(rules_path)
    data=build_dataset(doc,rules,date_order)
    output_dir.parent.mkdir(parents=True,exist_ok=True)
    scratch=Path(tempfile.mkdtemp(prefix='.ncfta-curate-',dir=output_dir.parent))
    try:
        write_csv(scratch/'events.csv',data['events'],EVENT_FIELDS)
        write_csv(scratch/'attributes.csv',data['attributes'],ATTRIBUTE_FIELDS+['deleted','disable_correlation','object_distribution','object_sharing_group_id'])
        write_csv(scratch/'fields.csv',data['fields'],FIELD_HEADERS)
        write_csv(scratch/'review_queue.csv',[r for r in data['fields'] if r['review_status']=='required'],FIELD_HEADERS)
        analyst_rows=[{**{k:v for k,v in e.items() if k not in ('fields','relationship_policy')},**{k:[v['value'] for v in vals] for k,vals in e['fields'].items()}} for e in data['analyst_events']]
        ah=['event_id','event_uuid','event_date','event_info','event_distribution','event_sharing_group_id','source_attribute_count','final_field_count','review_row_count']+data['field_names']
        write_csv(scratch/'analyst_events.csv',analyst_rows,ah)
        rr=[{**r,'rule_kind':kind,'rule_version':rules['rule_version']} for kind in ('rules','narrative_rules') for r in rules.get(kind,[])]
        write_csv(scratch/'mapping_rules.csv',rr,['rule_version','id','rule_kind','source_type','source_label','expected_categories','field','business_area','validator','labels','description'])
        for name,content in [('analyst_events.json',data['analyst_events']),('fields.json',data['fields']),('quality_summary.json',data['quality']),('mapping_rules.json',rules)]:
            (scratch/name).write_text(json.dumps(content,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        manifest=dict(schema_version='1.0.0',source_filename=source.name,source_sha256=hashlib.sha256(source_bytes).hexdigest(),
                      rule_version=rules['rule_version'],rules_sha256=hashlib.sha256(rules_path.read_bytes()).hexdigest(),
                      generated_at_utc=datetime.now(timezone.utc).isoformat(),date_order=date_order or 'unambiguous_only',
                      csv_policy='UTF-8 BOM; formula-like text prefixed with apostrophe. Import IDs and values as Text. JSON preserves exact source strings.',
                      output_files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(scratch.iterdir())})
        (scratch/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
        # Windows rename refuses an existing destination, including concurrent creation.
        scratch.rename(output_dir)
    except BaseException:
        shutil.rmtree(scratch)
        raise
    return data['quality']


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path)
    parser.add_argument('--output-dir',required=True,type=Path,help='New directory; existing directories are refused')
    parser.add_argument('--rules',type=Path,default=Path(__file__).with_name('ncfta_mapping_rules.json'))
    parser.add_argument('--date-order',choices=['MDY','DMY'],help='Only set after confirming the source slash-date convention')
    args=parser.parse_args()
    try:q=export_dataset(args.input,args.output_dir,args.rules,args.date_order)
    except (OSError,ValueError,KeyError,TypeError) as exc:parser.exit(1,f'Curated export failed: {exc}\n')
    print(f"Exported {q['event_count']} events, {q['source_attribute_count']} attributes, {q['final_field_count']} populated field rows, {q['review_row_count']} review rows.")
    print('Output directory:',args.output_dir)


if __name__=='__main__':main()
