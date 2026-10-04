from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import splunk_lab
from scripts.splunk_dataset import (
    BUNDLE, EXPECTED, ROOT, compare_results, export_bundle,
    load_bundle, normalize_results, python_results,
)


def test_export_matches_independent_expectations_and_checked_in_bundle(tmp_path: Path) -> None:
    manifest = export_bundle([ROOT / 'fixtures/days_1_2.jsonl', ROOT / 'fixtures/splunk_r1_boundaries.jsonl'],
                             tmp_path, 'section5-r1-v1', allow_rejections=True)
    checked, records = load_bundle(BUNDLE)
    assert manifest == checked
    assert (tmp_path / 'events.jsonl').read_bytes() == (BUNDLE / 'events.jsonl').read_bytes()
    actual = python_results(records)
    expected = json.loads(EXPECTED.read_text())['alerts']
    assert compare_results(records, expected, actual)['matches']
    assert len(actual) == 9
    assert next(r for r in actual if r['success_event_id'] == 'dense-success')['failure_count'] == 125
    assert manifest['event_count'] == 200
    assert sum(source['duplicates'] for source in manifest['sources']) == 2
    assert sum(len(source['rejected']) for source in manifest['sources']) == 1


def test_export_requires_explicit_rejection_policy(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match='rejected input'):
        export_bundle([ROOT / 'fixtures/days_1_2.jsonl'], tmp_path, 'rejected')


def test_export_preserves_casefold_null_and_microseconds() -> None:
    _, records = load_bundle(BUNDLE)
    by_id = {record['event_id']: record for record in records}
    assert by_id['casefold-f0']['attempted_account'] == 'strasse@example.test'
    assert by_id['null-org-f0']['organization_id'] is None
    assert by_id['literal-null-key-f0']['organization_id'] == '0:'
    assert by_id['bounds-low-minus']['occurred_at'] == '2026-09-17T12:49:59.999999Z'
    assert by_id['bounds-upper-plus']['occurred_at'] == '2026-09-17T13:00:00.000001Z'


def test_shuffled_source_and_later_replay_export_identical_content(tmp_path: Path) -> None:
    import random
    source = ROOT / 'fixtures/splunk_r1_boundaries.jsonl'
    lines = source.read_text().splitlines()
    random.Random(777).shuffle(lines)
    shuffled = tmp_path / 'shuffled.jsonl'
    shuffled.write_text('\n'.join(lines) + '\n')
    first = export_bundle([source], tmp_path / 'a', 'shuffle')
    second = export_bundle([shuffled], tmp_path / 'b', 'shuffle')
    assert first['file_sha256'] == second['file_sha256']
    assert first['content_sha256'] == second['content_sha256']


def test_bundle_tampering_is_rejected(tmp_path: Path) -> None:
    for name in ('manifest.json', 'events.jsonl'):
        (tmp_path / name).write_bytes((BUNDLE / name).read_bytes())
    with (tmp_path / 'events.jsonl').open('ab') as file:
        file.write(b'\n')
    with pytest.raises(ValueError, match='hash mismatch'):
        load_bundle(tmp_path)


def test_comparison_detects_missing_extra_and_reordered_evidence() -> None:
    _, records = load_bundle(BUNDLE)
    expected = json.loads(EXPECTED.read_text())['alerts']
    assert not compare_results(records, expected, python_results(records)[1:])['matches']
    rows = python_results(records)
    rows[0]['failure_event_ids'].reverse()
    rows[0]['evidence_event_ids'] = rows[0]['failure_event_ids'] + [rows[0]['success_event_id']]
    assert not compare_results(records, expected, rows)['matches']
    with pytest.raises(ValueError, match='duplicate success'):
        normalize_results(rows + rows[:1])
    with pytest.raises(ValueError, match='conflicting input'):
        normalize_results([{'result_type': 'error', 'error': 'conflicting_event_id'}])


def indexed(records):
    from datetime import datetime, timezone
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    rows = []
    for record in records:
        delta = datetime.fromisoformat(record['occurred_at'].replace('Z', '+00:00')) - epoch
        us = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
        rows.append({'_raw': json.dumps(record), 'indexed_us': str(us)})
    return rows


def test_index_validation_checks_multiplicity_content_and_time() -> None:
    _, records = load_bundle(BUNDLE)
    rows = indexed(records)
    splunk_lab.check_indexed(rows, records)
    splunk_lab.check_indexed(rows * 2, records, copies=2)
    for bad in (rows[:-1], rows[:-1] + rows[:1]):
        with pytest.raises(splunk_lab.SplunkError):
            splunk_lab.check_indexed(bad, records)
    rows[0]['indexed_us'] = str(int(rows[0]['indexed_us']) + 1)
    with pytest.raises(splunk_lab.SplunkError, match='microsecond'):
        splunk_lab.check_indexed(rows, records)
    rows = indexed(records)
    changed = json.loads(rows[0]['_raw'])
    changed['source_ip'] = '192.0.2.99'
    rows[0]['_raw'] = json.dumps(changed)
    with pytest.raises(splunk_lab.SplunkError, match='content differs'):
        splunk_lab.check_indexed(rows, records)


def test_guarded_import_skips_complete_and_rejects_partial(monkeypatch, tmp_path: Path) -> None:
    _, records = load_bundle(BUNDLE)
    monkeypatch.setattr(splunk_lab, 'RUNTIME', tmp_path)
    monkeypatch.setattr(splunk_lab, 'indexed_rows', lambda *args: indexed(records))
    monkeypatch.setattr(splunk_lab, 'submit', lambda *args: pytest.fail('must not submit'))
    assert splunk_lab.guarded_import() == {'state': 'already_imported', 'raw_count': 200}
    monkeypatch.setattr(splunk_lab, 'indexed_rows', lambda *args: indexed(records[:-1]))
    with pytest.raises(splunk_lab.SplunkError, match='incomplete'):
        splunk_lab.guarded_import()


def test_import_interruption_cannot_trigger_automatic_resubmit(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(splunk_lab, 'RUNTIME', tmp_path)
    monkeypatch.setattr(splunk_lab, 'indexed_rows', lambda *args: [])
    calls = []
    def fail(*args):
        calls.append(args)
        raise splunk_lab.SplunkError('connection lost after submit')
    monkeypatch.setattr(splunk_lab, 'submit', fail)
    with pytest.raises(splunk_lab.SplunkError, match='connection lost'):
        splunk_lab.guarded_import()
    with pytest.raises(splunk_lab.SplunkError, match='unresolved outcome'):
        splunk_lab.guarded_import()
    assert len(calls) == 1


def test_search_warnings_and_spl_injection_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(splunk_lab, 'request', lambda *args: json.dumps({'messages': [{'type': 'WARN', 'text': 'truncated'}]}))
    with pytest.raises(splunk_lab.SplunkError, match='warning'):
        splunk_lab.search('search anything')
    with pytest.raises(ValueError):
        splunk_lab.selection(splunk_lab.MAIN_INDEX, 'bad" | delete')


def test_first_import_records_pending_then_clears_it(monkeypatch, tmp_path: Path) -> None:
    manifest, records = load_bundle(BUNDLE)
    pending = tmp_path / (manifest['dataset_id'] + '.pending.json')
    monkeypatch.setattr(splunk_lab, 'RUNTIME', tmp_path)
    monkeypatch.setattr(splunk_lab, 'indexed_rows', lambda *args: [])
    calls = []
    def submit(*args):
        assert pending.exists()
        assert json.loads(pending.read_text())['file_sha256'] == manifest['file_sha256']
        calls.append(args)
    monkeypatch.setattr(splunk_lab, 'submit', submit)
    monkeypatch.setattr(splunk_lab, 'wait_indexed', lambda *args: indexed(records))
    assert splunk_lab.guarded_import() == {'state': 'imported', 'raw_count': 200}
    assert len(calls) == 1
    assert not pending.exists()


def test_completed_interrupted_import_recovers_without_resubmit(monkeypatch, tmp_path: Path) -> None:
    manifest, records = load_bundle(BUNDLE)
    pending = tmp_path / (manifest['dataset_id'] + '.pending.json')
    pending.write_text(json.dumps(manifest))
    monkeypatch.setattr(splunk_lab, 'RUNTIME', tmp_path)
    monkeypatch.setattr(splunk_lab, 'indexed_rows', lambda *args: indexed(records))
    monkeypatch.setattr(splunk_lab, 'submit', lambda *args: pytest.fail('must not resubmit'))
    assert splunk_lab.guarded_import()['state'] == 'already_imported'
    assert not pending.exists()


def test_api_export_bundle_uses_the_runtime_mount(tmp_path):
    assert splunk_lab.container_bundle_path(BUNDLE) == '/datasets/events.jsonl'
    assert splunk_lab.container_bundle_path(splunk_lab.RUNTIME / 'api-export') == '/parity-runtime/api-export/events.jsonl'
    with pytest.raises(ValueError, match='bundle must be inside'):
        splunk_lab.container_bundle_path(tmp_path)
