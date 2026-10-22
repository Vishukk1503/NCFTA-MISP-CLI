"""Read a small sample of MISP events from a specified sharing group."""
import argparse
from collections import Counter
from datetime import date, datetime, timezone
import getpass
import json
from pathlib import Path
import sys
from urllib.parse import urlparse

import requests


def extract_events(body, group_id, limit, start=None, end=None):
    if isinstance(body, dict):
        if 'error' in body or 'errors' in body:
            raise ValueError('API error')
        body = body.get('response')
    if not isinstance(body, list) or len(body) > limit:
        raise ValueError('Unexpected event response or server ignored sample limit')
    events = []
    for item in body:
        if not isinstance(item, dict):
            raise ValueError('Unexpected event entry')
        event = item.get('Event', item)
        if not isinstance(event, dict) or not event.get('id'):
            raise ValueError('Missing event identity')
        # Validate the filter locally before writing any returned intelligence.
        if str(event.get('sharing_group_id')) != str(group_id):
            raise ValueError('Returned event does not match the requested sharing group')
        if start or end:
            event_date = date.fromisoformat(event.get('date', ''))
            if (start and event_date < start) or (end and event_date > end):
                raise ValueError('Returned event does not match the requested date range')
        events.append({'Event': event})
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--group', type=int, default=6)
    parser.add_argument('--limit', type=int, default=3, help='Sample size, 1-10 (default 3)')
    parser.add_argument('--page', type=int, default=1)
    parser.add_argument('--from-date', type=date.fromisoformat, help='Inclusive event date, YYYY-MM-DD')
    parser.add_argument('--to-date', type=date.fromisoformat, help='Inclusive event date, YYYY-MM-DD')
    parser.add_argument('--all-pages', action='store_true', help='Continue until an empty page is returned')
    parser.add_argument('--url', default='https://misp.ncfta.net')
    parser.add_argument('--ca-bundle', type=Path)
    parser.add_argument('--timeout', type=float, default=60)
    parser.add_argument('--output-dir', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    if args.from_date and args.to_date and args.from_date > args.to_date:
        parser.error('--from-date must not be later than --to-date')
    if args.all_pages and args.page != 1:
        parser.error('--all-pages starts at page 1')
    base = args.url.strip().rstrip('/')
    parsed = urlparse(base)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment):
        parser.error('--url must be an HTTPS origin')
    if args.group < 1 or args.page < 1 or not 1 <= args.limit <= 10:
        parser.error('Positive group/page and limit between 1 and 10 required')
    if not 0 < args.timeout < float('inf'):
        parser.error('Timeout must be finite and positive')
    if args.ca_bundle and not args.ca_bundle.is_file():
        parser.error('CA bundle file does not exist')
    if not sys.stdin.isatty():
        parser.error('Run interactively to enter your key privately')
    key = getpass.getpass('NCFTA API key (hidden input): ').strip()
    if not key:
        parser.error('API key required')
    payload = {'returnFormat': 'json', 'sharinggroup': [str(args.group)],
               'page': args.page, 'limit': args.limit,
               'metadata': False, 'withAttachments': False}
    if args.from_date:
        payload['from'] = args.from_date.isoformat()
    if args.to_date:
        payload['to'] = args.to_date.isoformat()
    print(f'Requesting up to {args.limit} events from sharing group {args.group}, page {args.page}...')
    try:
        with requests.Session() as session:
            session.headers.update({'Authorization': key, 'Accept': 'application/json',
                                    'Content-Type': 'application/json'})
            events = []
            seen = set()
            page = args.page
            while True:
                payload['page'] = page
                response = session.post(base + '/events/restSearch', json=payload,
                                        timeout=args.timeout, allow_redirects=False,
                                        verify=str(args.ca_bundle) if args.ca_bundle else True)
                print(f'Page {page}: HTTP {response.status_code}')
                if response.status_code in (401, 403):
                    print('Authentication or event-search access denied. No data saved.')
                    return 1
                if response.status_code != 200:
                    print('Search unsuccessful. Redirects are refused; no data saved.')
                    return 1
                batch = extract_events(response.json(), args.group, args.limit, args.from_date, args.to_date)
                for wrapper in batch:
                    identity = str(wrapper['Event']['id'])
                    if identity in seen:
                        raise ValueError('Repeated event across pages; pagination is unstable')
                    seen.add(identity)
                events.extend(batch)
                print(f'  {len(batch)} events on page; {len(events)} events collected.')
                if not args.all_pages or not batch:
                    break
                page += 1
    except requests.exceptions.SSLError:
        print('TLS validation failed. Use --ca-bundle with a trusted CA PEM if required.')
        return 1
    except requests.exceptions.RequestException:
        print('Network request failed. Check VPN, DNS, proxy, firewall, or timeout.')
        return 1
    except ValueError:
        print('Response did not pass JSON, sample-limit, or sharing-group validation. No data saved.')
        return 1
    stamp = datetime.now(timezone.utc)
    result = {'retrieved_at_utc': stamp.isoformat(), 'server': base,
              'sharing_group_id': args.group, 'page': args.page,
              'requested_limit': args.limit, 'event_count': len(events),
              'event_date_from': str(args.from_date) if args.from_date else None,
              'event_date_to': str(args.to_date) if args.to_date else None,
              'all_pages': args.all_pages, 'last_page_requested': page,
              'attachments_requested': False, 'response': events}
    try:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        label = f'{args.from_date}_to_{args.to_date}' if args.from_date or args.to_date else 'sample'
        output = args.output_dir / f"ncfta-group{args.group}-{label}-{stamp.strftime('%Y%m%dT%H%M%S%fZ')}.json"
        with output.open('x', encoding='utf-8') as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
            handle.write('\n')
    except OSError:
        print('Cannot save sample to output directory.')
        return 1
    counts = Counter()
    object_count = report_count = 0
    for wrapper in events:
        event = wrapper['Event']
        attributes = list(event.get('Attribute') or [])
        objects = event.get('Object') or []
        object_count += len(objects)
        report_count += len(event.get('EventReport') or [])
        for obj in objects:
            attributes.extend(obj.get('Attribute') or [])
        counts.update(str(attribute.get('type', 'unknown')) for attribute in attributes)
    print(f'Saved {len(events)} events, {sum(counts.values())} attributes, {object_count} objects, {report_count} event reports.')
    print('Attribute types: ' + json.dumps(dict(counts), ensure_ascii=True))
    print(f'Sample file: {output}')
    if not events:
        print('No matching visible events on this page. This alone does not prove access was denied.')
    if args.all_pages:
        print('Pagination completed through an empty page for this query. The live dataset may change during retrieval.')
    else:
        print('This is a bounded sample, not a complete group export.')
    print('Date filters use the event date, not publication or modification date.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

