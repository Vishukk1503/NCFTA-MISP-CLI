"""Convert NCFTA MISP JSON exports to analysis-ready CSVs (offline, no API calls).

Creates separate event-level and attribute-level CSVs, preserving object context.
Original source JSON is never modified. Uses only Python standard library.
"""
import argparse
import csv
import json
from pathlib import Path

EVENT_FIELDS = [
    "sharing_group_id", "event_id", "event_uuid", "event_date",
    "event_info", "threat_level_id", "analysis", "published",
    "orgc_id", "orgc_name", "distribution", "event_timestamp",
    "event_publish_timestamp", "event_attribute_count",
]
ATTRIBUTE_FIELDS = EVENT_FIELDS[:-1] + [
    "attribute_id", "attribute_uuid", "attribute_type", "attribute_category",
    "attribute_value", "to_ids", "comment", "first_seen", "last_seen",
    "attribute_timestamp", "attribute_distribution", "object_id",
    "object_uuid", "object_name", "object_meta_category", "object_relation",
]


def cell(value):
    """Make nested values readable and protect spreadsheet formula injection."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, bool):
        return str(value).lower()
    value = str(value)
    if value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def events_from_document(doc):
    if isinstance(doc, list):
        items = doc
    elif isinstance(doc, dict):
        items = doc.get("response", doc.get("Event"))
        if items is None:
            if "id" in doc:
                items = [doc]
            else:
                raise ValueError("No 'response' or 'Event' data found")
        elif isinstance(items, dict):
            items = [items]
    else:
        raise ValueError("Expected MISP JSON object or array")
    if not isinstance(items, list):
        raise ValueError("Invalid MISP event collection")
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Invalid MISP event item")
        event = item.get("Event", item)
        if not isinstance(event, dict) or event.get("id") is None:
            raise ValueError("MISP event missing id")
        yield event


def event_row(event, fallback_group):
    org = event.get("Orgc") or {}
    if not isinstance(org, dict):
        org = {}
    return {
        "sharing_group_id": event.get("sharing_group_id") or fallback_group,
        "event_id": event.get("id"),
        "event_uuid": event.get("uuid"),
        "event_date": event.get("date"),
        "event_info": event.get("info"),
        "threat_level_id": event.get("threat_level_id"),
        "analysis": event.get("analysis"),
        "published": event.get("published"),
        "orgc_id": event.get("orgc_id"),
        "orgc_name": org.get("name"),
        "distribution": event.get("distribution"),
        "event_timestamp": event.get("timestamp"),
        "event_publish_timestamp": event.get("publish_timestamp"),
        "event_attribute_count": len(event.get("Attribute") or []) + sum(
            len(obj.get("Attribute") or []) for obj in (event.get("Object") or [])
            if isinstance(obj, dict)
        ),
    }


def attribute_row(base, attr, obj=None):
    obj = obj or {}
    fields = {
        "attribute_id": attr.get("id"),
        "attribute_uuid": attr.get("uuid"),
        "attribute_type": attr.get("type"),
        "attribute_category": attr.get("category"),
        "attribute_value": attr.get("value"),
        "to_ids": attr.get("to_ids"),
        "comment": attr.get("comment"),
        "first_seen": attr.get("first_seen"),
        "last_seen": attr.get("last_seen"),
        "attribute_timestamp": attr.get("timestamp"),
        "attribute_distribution": attr.get("distribution"),
        "object_id": obj.get("id"),
        "object_uuid": obj.get("uuid"),
        "object_name": obj.get("name"),
        "object_meta_category": obj.get("meta-category"),
        "object_relation": attr.get("object_relation"),
    }
    return {**base, **fields}


def export_csv(source, output_dir):
    doc = json.loads(source.read_text(encoding="utf-8-sig"))
    fallback_group = doc.get("sharing_group_id", "") if isinstance(doc, dict) else ""
    events = list(events_from_document(doc))
    output_dir.mkdir(parents=True, exist_ok=True)
    # Do not overwrite other exports; names are tied to the input filename.
    event_path = output_dir / f"{source.stem}_events.csv"
    attr_path = output_dir / f"{source.stem}_attributes.csv"
    event_count = attr_count = 0
    with event_path.open("w", encoding="utf-8-sig", newline="") as ef, \
         attr_path.open("w", encoding="utf-8-sig", newline="") as af:
        ew = csv.DictWriter(ef, fieldnames=EVENT_FIELDS)
        aw = csv.DictWriter(af, fieldnames=ATTRIBUTE_FIELDS)
        ew.writeheader()
        aw.writeheader()
        for event in events:
            base = event_row(event, fallback_group)
            ew.writerow({k: cell(base.get(k)) for k in EVENT_FIELDS})
            event_count += 1
            attr_base = {k: v for k, v in base.items() if k != "event_attribute_count"}
            for attr in event.get("Attribute") or []:
                if isinstance(attr, dict):
                    row = attribute_row(attr_base, attr)
                    aw.writerow({k: cell(row.get(k)) for k in ATTRIBUTE_FIELDS})
                    attr_count += 1
            for obj in event.get("Object") or []:
                if isinstance(obj, dict):
                    for attr in obj.get("Attribute") or []:
                        if isinstance(attr, dict):
                            row = attribute_row(attr_base, attr, obj)
                            aw.writerow({k: cell(row.get(k)) for k in ATTRIBUTE_FIELDS})
                            attr_count += 1
    return event_path, attr_path, event_count, attr_count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON file exported by ncfta_extract_sample.py")
    parser.add_argument("--output-dir", type=Path, help="Output directory (default: input folder)")
    args = parser.parse_args()
    if not args.input.is_file():
        parser.error("Input JSON file not found")
    try:
        event_path, attr_path, ec, ac = export_csv(
            args.input, args.output_dir or args.input.parent
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(1, f"Conversion failed: {exc}\n")
    print(f"Exported {ec} events to {event_path}")
    print(f"Exported {ac} attributes to {attr_path}")
    print("UTF-8 with BOM; one row per event and one row per attribute.")


if __name__ == "__main__":
    main()
