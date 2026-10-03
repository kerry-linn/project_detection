from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import timezone
from pathlib import Path
from typing import Any, Sequence

from detections.common import deduplicate_and_sort
from detections.failed_login_success import detect_failed_logins_followed_by_success
from security_events import parse_event, parse_jsonl

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / 'splunk' / 'artifacts'
EXPECTED = ROOT / 'fixtures' / 'expected' / 'splunk_r1.json'
MAX_EVENTS = 1000
FIELDS = ('success_event_id', 'organization_id', 'attempted_account', 'failure_count',
          'failure_event_ids', 'evidence_event_ids')
WRAPPER_FIELDS = {'dataset_id', 'dataset_content_sha256'}


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def jsonl_bytes(records: list[dict]) -> bytes:
    return b''.join(json_bytes(record) + b'\n' for record in records)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(event) -> dict:
    record = event.to_dict()
    for name in ('occurred_at', 'ingested_at'):
        record[name] = getattr(event, name).astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
    return record


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n', encoding='utf-8')


def export_bundle(paths: Sequence[Path], output: Path, dataset_id: str,
                  allow_rejections: bool = False) -> dict:
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}', dataset_id):
        raise ValueError('dataset ID must contain 1–80 letters, digits, underscores, or hyphens')
    events, sources = [], []
    for path in paths:
        parsed = parse_jsonl(path)
        if parsed.rejected and not allow_rejections:
            raise ValueError(f'{path.name}: rejected input; inspect it or explicitly allow rejections')
        events.extend(parsed.events)
        sources.append({'file': path.name, 'sha256': sha256(path.read_bytes()),
                        'lines': parsed.lines_read, 'accepted': len(parsed.events),
                        'rejected': [{'line': r.line_number, 'reason': r.reason} for r in parsed.rejected],
                        'duplicates': len(parsed.duplicates)})
    records = [canonical(event) for event in deduplicate_and_sort(events)]
    if not 0 < len(records) <= MAX_EVENTS:
        raise ValueError(f'parity bundles require 1–{MAX_EVENTS} unique events')
    content_hash = sha256(jsonl_bytes(records))
    exported = [dict(record, dataset_id=dataset_id, dataset_content_sha256=content_hash) for record in records]
    payload = jsonl_bytes(exported)
    manifest = {'format_version': 1, 'dataset_id': dataset_id, 'event_count': len(records),
                'content_sha256': content_hash, 'file_sha256': sha256(payload),
                'rule_id': 'R1_FAILED_LOGINS_FOLLOWED_BY_SUCCESS', 'rule_version': '1.0',
                'threshold': 5, 'window_microseconds': 600_000_000, 'sources': sources}
    output.mkdir(parents=True, exist_ok=True)
    (output / 'events.jsonl').write_bytes(payload)
    write_json(output / 'manifest.json', manifest)
    return manifest


def load_bundle(directory: Path) -> tuple[dict, list[dict]]:
    manifest = json.loads((directory / 'manifest.json').read_text())
    payload = (directory / 'events.jsonl').read_bytes()
    if manifest.get('format_version') != 1 or sha256(payload) != manifest.get('file_sha256'):
        raise ValueError('bundle format or file hash mismatch')
    records = [json.loads(line) for line in payload.splitlines()]
    if len(records) != manifest['event_count'] or not 0 < len(records) <= MAX_EVENTS:
        raise ValueError('bundle event count mismatch or exceeded fixture limit')
    canonical_records = []
    for record in records:
        if (record.get('dataset_id') != manifest['dataset_id']
                or record.get('dataset_content_sha256') != manifest['content_sha256']):
            raise ValueError('dataset identity or content hash mismatch')
        raw = {key: value for key, value in record.items() if key not in WRAPPER_FIELDS}
        normalized = canonical(parse_event(raw))
        if raw != normalized:
            raise ValueError('exported event is not canonical')
        canonical_records.append(normalized)
    if len({r['event_id'] for r in records}) != len(records):
        raise ValueError('bundle contains duplicate event IDs')
    if canonical_records != sorted(canonical_records, key=lambda r: (r['occurred_at'], r['event_id'])):
        raise ValueError('bundle is not ordered by event time and event ID')
    if sha256(jsonl_bytes(canonical_records)) != manifest['content_sha256']:
        raise ValueError('canonical content hash mismatch')
    if (manifest['rule_id'], manifest['rule_version'], manifest['threshold'], manifest['window_microseconds']) != (
            'R1_FAILED_LOGINS_FOLLOWED_BY_SUCCESS', '1.0', 5, 600_000_000):
        raise ValueError('unsupported rule configuration')
    return manifest, records


def python_results(records: list[dict]) -> list[dict]:
    events = [parse_event({k: v for k, v in record.items() if k not in WRAPPER_FIELDS}) for record in records]
    return normalize_results([alert.to_dict() for alert in detect_failed_logins_followed_by_success(events)])


def normalize_results(rows: list[dict]) -> list[dict]:
    normalized = []
    for row in rows:
        if row.get('result_type') == 'error':
            raise ValueError('Splunk reported invalid or conflicting input')
        item = {key: row.get(key) for key in FIELDS}
        if not isinstance(item['success_event_id'], str) or not isinstance(item['attempted_account'], str):
            raise ValueError('malformed result identity')
        item['failure_count'] = int(item['failure_count'])
        for key in ('failure_event_ids', 'evidence_event_ids'):
            if isinstance(item[key], str):
                item[key] = [item[key]]
            if not isinstance(item[key], list) or not all(isinstance(v, str) for v in item[key]):
                raise ValueError('malformed evidence IDs')
        if (len(item['failure_event_ids']) != item['failure_count']
                or item['evidence_event_ids'] != item['failure_event_ids'] + [item['success_event_id']]
                or len(set(item['evidence_event_ids'])) != len(item['evidence_event_ids'])):
            raise ValueError('evidence counts or construction are inconsistent')
        normalized.append(item)
    if len({r['success_event_id'] for r in normalized}) != len(normalized):
        raise ValueError('duplicate success in detection results')
    return sorted(normalized, key=lambda r: r['success_event_id'])


def compare_results(records: list[dict], expected: list[dict], splunk: list[dict]) -> dict:
    expected_rows = normalize_results(expected)
    python_rows = python_results(records)
    splunk_rows = normalize_results(splunk)
    mismatches = []
    for name, rows in (('python', python_rows), ('splunk', splunk_rows)):
        wanted = {r['success_event_id']: r for r in expected_rows}
        actual = {r['success_event_id']: r for r in rows}
        for key in sorted(wanted.keys() | actual.keys()):
            if wanted.get(key) != actual.get(key):
                mismatches.append({'engine': name, 'success_event_id': key,
                                   'expected': wanted.get(key), 'actual': actual.get(key)})
    return {'matches': not mismatches, 'expected_alerts': len(expected_rows),
            'python_alerts': len(python_rows), 'splunk_alerts': len(splunk_rows),
            'mismatches': mismatches}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Export canonical Splunk fixtures or compare saved SPL results')
    commands = parser.add_subparsers(dest='command', required=True)
    export = commands.add_parser('export')
    export.add_argument('paths', nargs='+', type=Path)
    export.add_argument('--output', type=Path, default=BUNDLE)
    export.add_argument('--dataset-id', default='section5-r1-v1')
    export.add_argument('--allow-rejections', action='store_true')
    compare = commands.add_parser('compare')
    compare.add_argument('results', type=Path)
    compare.add_argument('--bundle', type=Path, default=BUNDLE)
    compare.add_argument('--expected', type=Path, default=EXPECTED)
    args = parser.parse_args(argv)
    try:
        if args.command == 'export':
            report = export_bundle(args.paths, args.output, args.dataset_id, args.allow_rejections)
        else:
            _, records = load_bundle(args.bundle)
            report = compare_results(records, json.loads(args.expected.read_text())['alerts'], json.loads(args.results.read_text()))
        print(json.dumps(report, indent=2))
        return 0 if report.get('matches', True) else 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({'error': str(error)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
