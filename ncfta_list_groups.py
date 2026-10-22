"""List NCFTA MISP sharing groups visible to an API key (read-only)."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests

PRIORITY = {'6': 'Cyfin', '7': 'RAOLFI', '8': 'TNT', '9': 'DGA'}


def parse_groups(body):
    """Accept MISP's documented response and common index wrappers."""
    if isinstance(body, dict):
        if 'error' in body or 'errors' in body:
            raise ValueError('MISP returned an API error.')
        body = body.get('response', body.get('SharingGroup'))
    if isinstance(body, dict):
        if 'error' in body or 'errors' in body:
            raise ValueError('MISP returned an API error.')
        body = body.get('SharingGroup', body.get('sharing_groups'))
    if not isinstance(body, list):
        raise ValueError('Unexpected sharing-group response; no access conclusions can be drawn.')
    groups = {}
    for item in body:
        if not isinstance(item, dict):
            raise ValueError('Unexpected sharing-group entry.')
        group = item.get('SharingGroup', item)
        if not isinstance(group, dict) or 'id' not in group or 'name' not in group:
            raise ValueError('Sharing-group entry is missing its ID or name.')
        group_id = str(group['id'])
        if not group_id.isdigit():
            raise ValueError('Unexpected sharing-group ID.')
        # Keep only group-level fields, excluding member organisations and servers.
        groups[group_id] = {k: group.get(k) for k in
                            ('id', 'name', 'active', 'description', 'releasability')}
        groups[group_id]['id'] = group_id
    return sorted(groups.values(), key=lambda g: int(g['id']))


def clean(value):
    # Escape terminal control characters in server-supplied text.
    return json.dumps(str(value), ensure_ascii=True)[1:-1]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='https://misp.ncfta.net')
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--ca-bundle', type=Path, help='Trusted corporate CA PEM bundle')
    parser.add_argument('--details', action='store_true', help='Print description and releasability')
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--groups', nargs='+', type=int, default=[6, 7, 8, 9],
                           metavar='ID', help='Group IDs to display (default: 6 7 8 9)')
    selection.add_argument('--all', action='store_true', help='Display all returned groups')
    parser.add_argument('--output', type=Path, help='Optionally save selected group metadata as JSON')
    args = parser.parse_args(argv)
    if any(group_id <= 0 for group_id in args.groups):
        parser.error('--groups IDs must be positive integers')
    base = args.url.strip().rstrip('/')
    parsed = urlparse(base)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment):
        parser.error('--url must be an HTTPS origin, such as https://misp.ncfta.net')
    if not 0 < args.timeout < float('inf'):
        parser.error('--timeout must be finite and positive')
    if args.ca_bundle and not args.ca_bundle.is_file():
        parser.error('--ca-bundle must point to an existing PEM file')
    if not sys.stdin.isatty():
        parser.error('Run in an interactive terminal so the API key can be entered privately.')
    key = getpass.getpass('NCFTA API key (hidden input): ').strip()
    if not key:
        parser.error('An API key is required')
    try:
        with requests.Session() as session:
            session.headers.update({'Authorization': key, 'Accept': 'application/json',
                                    'User-Agent': 'NCFTA-ReadOnly-Group-Discovery/1.0'})
            response = session.get(base + '/sharing_groups', timeout=args.timeout,
                                   verify=str(args.ca_bundle) if args.ca_bundle else True,
                                   allow_redirects=False)
            if response.status_code in (401, 403):
                print('Access denied: check the key, API permissions, VPN, and IP allowlisting.', file=sys.stderr)
                return 1
            if 300 <= response.status_code < 400:
                print('Redirect refused. Check the endpoint; the API key was not forwarded.', file=sys.stderr)
                return 1
            if response.status_code != 200:
                print(f'Group listing failed: HTTP {response.status_code}. No entitlement conclusion is possible.', file=sys.stderr)
                return 1
            groups = parse_groups(response.json())
    except requests.exceptions.SSLError:
        print('TLS verification failed. Supply a trusted --ca-bundle; verification remains enabled.', file=sys.stderr)
        return 1
    except requests.exceptions.RequestException:
        print('Network request failed. Check DNS, VPN, firewall, proxy, and server availability.', file=sys.stderr)
        return 1
    except ValueError:
        # Never print a response body or exception containing request credentials.
        print('Invalid or unrecognized JSON sharing-group response.', file=sys.stderr)
        return 1

    visible = {g['id'] for g in groups}
    selected_ids = {str(group_id) for group_id in args.groups}
    selected = groups if args.all else [g for g in groups if g['id'] in selected_ids]
    print(f'\nSharing groups returned by this server: {len(groups)}')
    print(f'Groups matching your selection: {len(selected)}')
    print('ID\tActive\tName')
    for group in selected:
        print(f"{group['id']}\t{clean(group['active'])}\t{clean(group['name'])}")
        if args.details:
            print('  Description: ' + clean(group['description']))
            print('  Releasability: ' + clean(group['releasability']))
    print('\nRequested group checks:')
    check_ids = list(PRIORITY) if args.all else sorted(selected_ids, key=int)
    for group_id in check_ids:
        name = PRIORITY.get(group_id, 'custom group')
        print(f"  {group_id} ({name}): {'RETURNED' if group_id in visible else 'NOT RETURNED'}")
    print('\nGroup visibility does not prove access to every event or attribute in that group.')
    print('NOT RETURNED does not by itself prove entitlement was denied; confirm with NCFTA.')
    if args.output:
        try:
            args.output.write_text(json.dumps({'server': base, 'groups': selected}, indent=2) + '\n', encoding='utf-8')
        except OSError:
            print('Could not write the requested output file.', file=sys.stderr)
            return 1
        print('Selected group metadata saved. Handle it under your NCFTA sharing rules.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

