# NCFTA MISP CLI

Read-only Python tools for listing sharing groups and extracting authorized NCFTA MISP events using the official PyMISP client. The offline CSV converter uses only Python's standard library.

## Install

Requires Python 3.10 or newer.

```console
python -m pip install --upgrade -r requirements.txt
```

Keep `ncfta_client.py` beside both CLI scripts. The shared client calls PyMISP's `sharing_groups()` and `search()` methods with dictionary responses to preserve the existing JSON format.

PyMISP performs read-only startup checks for the recommended client version, server version, current user/role, and attribute types. NCFTA must permit those endpoints as well as the group/event endpoints. Live compatibility must be checked with your own key; automated tests mock the server and startup lookups.

The shared HTTPS adapter refuses redirects, other origins, and write operations. Only GET requests and the read-only POST to `/events/restSearch` are allowed. PyMISP's response/header logging is suppressed during the connection to avoid printing credentials or returned intelligence.

## List groups

```console
python ncfta_list_groups.py --all --details
python ncfta_list_groups.py --groups 6 7 8 --details
```

## Extract events for one date

```console
python ncfta_extract_sample.py --group 6 --from-date 2026-09-01 --to-date 2026-09-01 --limit 10 --all-pages
```

Replace `--group 6` with `--group 7` or `--group 8` to request those groups. The server enforces your key's permissions.

## Extract a month

```console
python ncfta_extract_sample.py --group 6 --from-date 2026-09-01 --to-date 2026-09-30 --limit 10 --all-pages
```

Enter the API key privately at the hidden prompt; it is not saved. TLS verification stays enabled, redirects are refused, and no remote records are modified. If needed, provide a trusted corporate CA PEM with `--ca-bundle`.

`--limit` is the number of events per request (1–10, default 3), not the total number of events or attributes. `--all-pages` continues until an empty page. Results are saved only after pagination finishes; interrupted or failed runs do not save partial data. The live data can change during pagination, so the result is not a transactional snapshot.

Date filters use the MISP event `date`, which may differ from the actual crime date in an attribute or narrative. Returned event group and date are validated locally. An event can contain many typed attributes and optional objects. Sharing an event does not establish ownership or a transaction relationship between all attributes.

JSON exports include returned attributes and objects; attachment binary contents are not requested. Use `--output-dir` for a different local output folder. Exports may contain personal and financial information; follow NCFTA's storage, retention and redistribution rules. No API keys or source intelligence are included in this upload package.

## References

- https://www.misp-project.org/openapi/
- https://misp-standard.org/formats/core/
- https://github.com/MISP/PyMISP


## Offline CSV conversion

Convert a saved export without contacting NCFTA:

```console
python ncfta_json_to_csv.py path/to/export.json --output-dir csv-export
```

Creates separate event and attribute CSVs. In the attribute CSV, `sharing_group_id` is the parent event's group; `attribute_sharing_group_id` and `attribute_distribution` preserve the attribute's own sharing settings. A group ID of 0 is preserved; interpret it together with distribution (for example, 5 means inherit event permissions).

If either output CSV already exists, conversion fails without overwriting it. Choose another output directory for a new export. Newly created partial outputs are removed if conversion fails.

Run regression tests:

```console
python -m unittest discover -p "test*.py" -v
```


