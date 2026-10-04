from __future__ import annotations

import argparse
import fcntl
import json
import random
import re
import subprocess
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from scripts.splunk_dataset import (
    BUNDLE, EXPECTED, ROOT, compare_results, jsonl_bytes, load_bundle,
    normalize_results, write_json,
)

SPLUNK = ROOT / 'splunk'
RUNTIME = SPLUNK / '.runtime'
MAIN_INDEX = 'detection_lab_s1'
REPLAY_INDEX = 'detection_lab_s1_replay'
_REMOTE = r'''
import base64, json, os, ssl, sys, urllib.error, urllib.parse, urllib.request
request = json.load(sys.stdin)
context = ssl.create_default_context(cafile='/opt/splunk/etc/auth/cacert.pem')
# Splunk's bundled v1 CA lacks the extensions required by Python 3.13 strict mode.
context.verify_flags &= ~ssl.VERIFY_X509_STRICT
context.check_hostname = False
password = os.environ['SPLUNK_PASSWORD']
auth = base64.b64encode(('admin:' + password).encode()).decode()
params = dict(request['params'], output_mode='json')
data = urllib.parse.urlencode(params).encode() if request['method']=='POST' else None
url = 'https://127.0.0.1:8089' + request['path']
if data is None: url += '?' + urllib.parse.urlencode(params)
req = urllib.request.Request(url, data=data, headers={'Authorization': 'Basic ' + auth}, method=request['method'])
try:
    with urllib.request.urlopen(req, context=context, timeout=120) as response:
        sys.stdout.write(response.read().decode())
except urllib.error.HTTPError as error:
    print(json.dumps({'transport_error': 'HTTP ' + str(error.code)}))
    sys.exit(1)
except Exception:
    print(json.dumps({'transport_error': 'Splunk local connection failed'}))
    sys.exit(1)
'''


class SplunkError(RuntimeError):
    pass


def request(path: str, params: dict, method: str = 'POST') -> str:
    command = ['docker', 'compose', '--env-file', str(SPLUNK / '.env'),
               '-f', str(SPLUNK / 'compose.yaml'), 'exec', '-T', '--user', 'splunk', 'splunk',
               'python3', '-c', _REMOTE]
    try:
        result = subprocess.run(command, input=json.dumps({'path': path, 'params': params, 'method': method}),
                                text=True, capture_output=True, timeout=150, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SplunkError('Docker/Splunk unavailable or timed out') from error
    if result.returncode:
        raise SplunkError('Docker/Splunk request failed; verify the container is ready and its local credentials are current')
    return result.stdout


def search(query: str) -> list[dict]:
    output = request('/services/search/jobs/export', {'search': query, 'exec_mode': 'oneshot'})
    rows = []
    for line in output.splitlines():
        message = json.loads(line)
        if message.get('error') or message.get('transport_error'):
            raise SplunkError('Splunk search failed')
        for entry in message.get('messages', []):
            if entry.get('type', '').upper() in {'WARN', 'ERROR', 'FATAL'}:
                raise SplunkError('Splunk search emitted a warning/error; parity is unverified')
        if message.get('preview'):
            continue
        if 'result' in message:
            rows.append(message['result'])
    return rows


def selection(index: str, dataset_id: str) -> str:
    if index not in {MAIN_INDEX, REPLAY_INDEX} or not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}', dataset_id):
        raise ValueError('invalid lab index or dataset ID')
    return f'search index={index} sourcetype="detection_lab:json" dataset_id="{dataset_id}" earliest=0 latest=+10y'


def indexed_rows(index: str, dataset_id: str) -> list[dict]:
    return search(selection(index, dataset_id) + '\n| eval indexed_us=printf("%.0f",_time*1000000)\n| table _raw indexed_us')


def check_indexed(rows: list[dict], records: list[dict], copies: int = 1) -> None:
    expected = {record['event_id']: record for record in records}
    seen = {key: 0 for key in expected}
    if len(rows) != len(records) * copies:
        raise SplunkError('indexed count is incomplete or contains unexpected replays')
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    for row in rows:
        record = json.loads(row['_raw'])
        if record != expected.get(record.get('event_id')):
            raise SplunkError('indexed content differs from the canonical bundle')
        delta = datetime.fromisoformat(record['occurred_at'].replace('Z', '+00:00')) - epoch
        expected_us = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
        if int(row['indexed_us']) != expected_us:
            raise SplunkError('occurred_at was not indexed at microsecond precision')
        seen[record['event_id']] += 1
    if any(count != copies for count in seen.values()):
        raise SplunkError('indexed event IDs do not match the bundle multiplicity')


def submit(path: str, index: str) -> None:
    response = json.loads(request('/services/data/inputs/oneshot',
                                  {'name': path, 'index': index, 'sourcetype': 'detection_lab:json'}))
    if any(message.get('type', '').upper() in {'ERROR', 'FATAL'} for message in response.get('messages', [])):
        raise SplunkError('Splunk refused the fixture import')


def wait_indexed(index: str, dataset_id: str, count: int) -> list[dict]:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        rows = indexed_rows(index, dataset_id)
        if len(rows) >= count:
            return rows
        time.sleep(1)
    raise SplunkError('indexing did not reach the expected count; import state remains pending')


@contextmanager
def import_lock():
    RUNTIME.mkdir(parents=True, exist_ok=True)
    with (RUNTIME / 'import.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def container_bundle_path(bundle: Path) -> str:
    path = (bundle / 'events.jsonl').resolve()
    for host, container in ((BUNDLE, '/datasets'), (RUNTIME, '/parity-runtime')):
        try:
            return container + '/' + path.relative_to(host.resolve()).as_posix()
        except ValueError:
            pass
    raise ValueError('bundle must be inside splunk/artifacts or splunk/.runtime')


def guarded_import(bundle: Path = BUNDLE) -> dict:
    manifest, records = load_bundle(bundle)
    source_path = container_bundle_path(bundle)
    dataset_id = manifest['dataset_id']
    selection(MAIN_INDEX, dataset_id)
    with import_lock():
        pending = RUNTIME / f'{dataset_id}.pending.json'
        rows = indexed_rows(MAIN_INDEX, dataset_id)
        if rows:
            check_indexed(rows, records)
            pending.unlink(missing_ok=True)
            return {'state': 'already_imported', 'raw_count': len(rows)}
        if pending.exists():
            raise SplunkError('an earlier import has an unresolved outcome; inspect it before using a new dataset ID')
        write_json(pending, manifest)
        submit(source_path, MAIN_INDEX)
        rows = wait_indexed(MAIN_INDEX, dataset_id, len(records))
        check_indexed(rows, records)
        pending.unlink()
        return {'state': 'imported', 'raw_count': len(rows)}


def run_saved(name: str, index: str, dataset_id: str) -> list[dict]:
    selection(index, dataset_id)
    query = (SPLUNK / name).read_text()
    return search(query.replace('__INDEX__', index).replace('__DATASET__', dataset_id))


def r1(index: str, dataset_id: str) -> list[dict]:
    return run_saved('r1_failed_login_success.spl', index, dataset_id)


def verify(bundle: Path = BUNDLE, results: Path = SPLUNK / 'results') -> dict:
    manifest, records = load_bundle(bundle)
    expected = json.loads(EXPECTED.read_text())['alerts']
    write_json(results / 'verification.json',
               {'verified': False, 'state': 'in_progress', 'dataset_id': manifest['dataset_id']})
    version = json.loads(request('/services/server/info', {}, 'GET'))['entry'][0]['content']['version']
    if version != '10.4.3':
        raise SplunkError('verification requires the pinned Splunk 10.4.3 version')
    first = guarded_import(bundle)
    second = guarded_import(bundle)
    if first['raw_count'] != second['raw_count'] or second['state'] != 'already_imported':
        raise SplunkError('guarded replay changed indexed counts')
    original = r1(MAIN_INDEX, manifest['dataset_id'])
    comparison = compare_results(records, expected, original)
    write_json(results / 'comparison.json', comparison)
    write_json(results / 'r1.json', original)
    if not comparison['matches']:
        raise SplunkError('Splunk/Python/expected comparison failed; see results/comparison.json')

    auxiliary = {}
    for name in ('account_activity', 'failed_logins', 'denied_resources', 'evidence'):
        result = run_saved(name + '.spl', MAIN_INDEX, manifest['dataset_id'])
        write_json(results / (name + '.json'), result)
        auxiliary[name] = result
    account_ids = [r['event_id'] for r in records if r['attempted_account'] == 'alice@example.test']
    if [r['event_id'] for r in auxiliary['account_activity']] != account_ids:
        raise SplunkError('account activity search differs from the canonical timeline')
    if [r['event_id'] for r in auxiliary['evidence']] != ['evt-004', 'evt-005', 'evt-006', 'evt-007', 'evt-008', 'evt-009']:
        raise SplunkError('evidence search differs from the hand checked IDs')
    if sum(int(r['failures']) for r in auxiliary['failed_logins']) != sum(r['event_type'] == 'login_failed' for r in records):
        raise SplunkError('failed login summary omitted or duplicated events')
    if sum(int(r['denials']) for r in auxiliary['denied_resources']) != sum(r['event_type'] == 'access_denied' for r in records):
        raise SplunkError('denied resource summary omitted or duplicated events')

    replay_id = 's1-replay-' + uuid.uuid4().hex[:12]
    replay_records = [dict(record, dataset_id=replay_id) for record in records]
    shuffled = replay_records.copy()
    random.Random(5005).shuffle(shuffled)
    replay_file = RUNTIME / f'{replay_id}.jsonl'
    replay_file.write_bytes(jsonl_bytes(shuffled))
    submit('/parity-runtime/' + replay_file.name, REPLAY_INDEX)
    rows = wait_indexed(REPLAY_INDEX, replay_id, len(records))
    check_indexed(rows, replay_records)
    shuffled_results = r1(REPLAY_INDEX, replay_id)
    if normalize_results(shuffled_results) != normalize_results(original):
        raise SplunkError('shuffled ingestion changed R1 results')
    submit('/parity-runtime/' + replay_file.name, REPLAY_INDEX)
    rows = wait_indexed(REPLAY_INDEX, replay_id, len(records) * 2)
    check_indexed(rows, replay_records, copies=2)
    replay_results = r1(REPLAY_INDEX, replay_id)
    if normalize_results(replay_results) != normalize_results(original):
        raise SplunkError('deliberate replay changed R1 results')
    write_json(results / 'r1_replay.json', replay_results)

    conflict = dict(replay_records[0], source_ip='192.0.2.99')
    conflict_file = RUNTIME / f'{replay_id}-conflict.jsonl'
    conflict_file.write_bytes(jsonl_bytes([conflict]))
    submit('/parity-runtime/' + conflict_file.name, REPLAY_INDEX)
    wait_indexed(REPLAY_INDEX, replay_id, len(records) * 2 + 1)
    conflict_results = r1(REPLAY_INDEX, replay_id)
    if (not any(row.get('error') == 'conflicting_event_id' for row in conflict_results)
            or any(row.get('result_type') != 'error' for row in conflict_results)):
        raise SplunkError('SPL did not flag a conflicting event ID')
    write_json(results / 'conflict.json', conflict_results)
    report = {'verified': True, 'auxiliary_searches_verified': list(auxiliary), 'verified_at': datetime.now(timezone.utc).isoformat(), 'splunk_version': version,
              'dataset_id': manifest['dataset_id'], 'file_sha256': manifest['file_sha256'],
              'event_count': len(records), 'comparison': comparison,
              'guarded_import': first, 'guarded_reimport': second,
              'timestamp_precision': 'all exported event times matched at integer microseconds',
              'shuffled_input_matches': True, 'replay_dataset_id': replay_id,
              'replay_raw_count_before': len(records), 'replay_raw_count_after': len(rows),
              'replay_results_match': True, 'conflicting_content_flagged': True}
    write_json(results / 'verification.json', report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Import and verify the isolated local Splunk fixture')
    parser.add_argument('command', choices=('import', 'verify'))
    parser.add_argument('--bundle', type=Path, default=BUNDLE)
    parser.add_argument('--results', type=Path, default=SPLUNK / 'results')
    args = parser.parse_args(argv)
    try:
        report = guarded_import(args.bundle) if args.command == 'import' else verify(args.bundle, args.results)
        print(json.dumps(report, indent=2))
        return 0
    except (SplunkError, ValueError, KeyError, OSError) as error:
        if args.command == 'verify':
            write_json(args.results / 'verification.json',
                       {'verified': False, 'state': 'failed', 'error': str(error)})
        print(json.dumps({'error': str(error)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
