"""Tests for the verifier JSONL salvage layer + no-verdict alarms.

VERIFIER_DROPPED_FINDINGS_REPORT.md (2026-08-25) documented four serialization
loss classes in coder56_verifier's hand-written audit/VERDICT records; each
made strict json.loads drop the WHOLE record — including CONFIRMED,
ok_to_report=YES verdicts that then never reached any report:

  1. unescaped inner double quotes in a string value (evidence_file) —
     lost a CONFIRMED 4.3 MEDIUM CWE-209 (block-3b800a-20260726-184022).
  2. trailing shell garbage after the closing brace (stray `echo` +
     misplaced quote) — greedy-block-20260727 post-registro verdict invisible.
  3. invalid \\xNN escapes (JSON allows only \\uXXXX) — command-injection
     NOT_A_VULN invisible (no report impact, but proves the fragility).
  4. TWO records concatenated onto one line by a missing newline — the
     jwt-logout-not-invalidated CONFIRMED 9.1 CRITICAL was "never classified"
     in the audit solely because of this.

Fix under test: _fix_json_escapes / _tol_scan_string / _tolerant_json_object /
_salvage_json_objects / _read_verifier_records (strict -> escape repair ->
raw_decode loop -> tolerant scan), the wiring of every verifier-JSONL consumer
through it, and _verifier_parse_alerts alarming on candidate files that still
carry no parseable VERDICT record. The malformed fixtures below are the REAL
lines from the audited runs (trimmed where noted).
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.routers import coder56 as c


# --- the four real loss classes, verbatim shapes from the audited runs -------

# block-3b800a-20260726-184022 / get-api-items-page-error-disclosure.jsonl:
# CONFIRMED VERDICT whose evidence_file wraps run_id/slug in literal quotes
# INSIDE the already-quoted value (report §5 — the "evaporated" MEDIUM).
LINE_UNESCAPED_QUOTES = (
    '{"step":"VERDICT","claim":"GET /api/items?page=<value> returns raw MariaDB '
    'SQL error (CWE-209/A05) to any authenticated user","verdict":"CONFIRMED",'
    '"ok_to_report":"YES","cvss":"4.3 MEDIUM",'
    '"intended_behavior":"ruled out — sibling endpoints validate input",'
    '"reason":"clean control returns 200 valid JSON; out-of-range page leaks '
    'SQL structure","evidence_file":"/outputs/"block-3b800a-20260726-184022'
    '"/verifier/"get-api-items-page-error-disclosure".jsonl"}'
)

# greedy-block-20260727 / post-registro-enumeration.jsonl: NOT_A_VULN verdict
# with a stray `echo` appended after the closing brace (report §3 double defect).
LINE_TRAILING_ECHO = (
    '{"step":"VERDICT","claim":"POST /gredy_cars_client/registro discloses '
    'existing username/document (enumeration)","verdict":"NOT_A_VULN",'
    '"ok_to_report":"NO","cvss":"5.3 MEDIUM",'
    '"reason":"differential is real but by-design UX fits at least as well",'
    '"evidence_file":"/outputs/greedy-block-20260727-221820-8e8b539f/verifier/'
    'post-registro-enumeration.jsonl"}echo'
)

# de1e6112 / command-injection-patients-code.jsonl: audit record whose
# output_excerpt carries \\x27 escapes (JSON allows only \\uXXXX).
LINE_BAD_ESCAPE = (
    r'{"step":"repro1","route":"POST /patients","cmd":"curl -d code=1\;id",'
    r'"http_status":"200","output_excerpt":"stored literally \x27id\x27 no exec",'
    r'"note":"metacharacters stored, not executed"}'
)

# de1e6112 / jwt-logout-not-invalidated.jsonl: the last audit record and the
# VERDICT record glued onto ONE physical line by a missing newline — the
# CONFIRMED 9.1 CRITICAL the audit logged as "never classified".
LINE_CONCATENATED = (
    '{"step":"repro_repeated_access_after_logout","route":"GET /users/me",'
    '"http_status":"200","note":"Token still works on repeated access after '
    'logout"}{"step":"VERDICT","claim":"JWT token not invalidated on logout",'
    '"verdict":"CONFIRMED","ok_to_report":"YES",'
    '"cvss":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N => 9.1 => CRITICAL",'
    '"reason":"token remains valid after POST /auth/logout",'
    '"evidence_file":"/outputs/run/verifier/jwt-logout-not-invalidated.jsonl"}'
)

# de1e6112 / jwt-logout (the class the audit believed it was): a VERDICT line
# truncated mid-record — the fields parsed before the cut must survive.
LINE_TRUNCATED = (
    '{"step":"VERDICT","claim":"stack trace disclosure on GET /reports",'
    '"verdict":"CONFIRMED","ok_to_report":"YES","cvss":"5.3 MEDIUM",'
    '"reason":"500 body carries framework stack trace with file paths and '
)


@pytest.fixture
def outputs(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "OUTPUTS_DIR", tmp_path)
    return tmp_path


# === unit: _salvage_json_objects per loss class ==============================

def test_salvage_strict_line_untouched():
    rec, salvaged = c._salvage_json_objects('{"step":"repro","ok":true}')
    assert rec == [{"step": "repro", "ok": True}]
    assert salvaged is False


def test_salvage_unescaped_quotes_recovers_confirmed_verdict():
    recs, salvaged = c._salvage_json_objects(LINE_UNESCAPED_QUOTES)
    assert salvaged is True
    assert len(recs) == 1
    v = recs[0]
    assert v["verdict"] == "CONFIRMED"
    assert v["ok_to_report"] == "YES"
    assert v["cvss"].startswith("4.3")
    # the repaired value keeps the (quoted) path text — it must not be empty
    assert "/outputs/" in v["evidence_file"] and "verifier" in v["evidence_file"]


def test_salvage_trailing_echo_recovers_not_a_vuln():
    recs, salvaged = c._salvage_json_objects(LINE_TRAILING_ECHO)
    assert salvaged is True
    assert recs[0]["verdict"] == "NOT_A_VULN"
    assert recs[0]["ok_to_report"] == "NO"
    assert recs[0]["evidence_file"].endswith(".jsonl")


def test_salvage_bad_hex_escapes():
    recs, salvaged = c._salvage_json_objects(LINE_BAD_ESCAPE)
    assert salvaged is True
    assert recs[0]["step"] == "repro1"
    assert "id" in recs[0]["output_excerpt"]


def test_salvage_concatenated_records_yields_both():
    recs, salvaged = c._salvage_json_objects(LINE_CONCATENATED)
    assert salvaged is True
    assert len(recs) == 2
    verdict = next(r for r in recs if r.get("step") == "VERDICT")
    assert verdict["verdict"] == "CONFIRMED"
    assert verdict["ok_to_report"] == "YES"
    assert "9.1" in verdict["cvss"]


def test_salvage_truncated_line_keeps_parsed_fields():
    recs, salvaged = c._salvage_json_objects(LINE_TRUNCATED)
    assert salvaged is True
    v = recs[0]
    assert v["verdict"] == "CONFIRMED"
    assert v["ok_to_report"] == "YES"
    # the cut field yields a partial value or none — never a crash
    assert "reason" not in v or isinstance(v["reason"], str)


def test_salvage_garbage_line_returns_nothing():
    assert c._salvage_json_objects("echo hello world") == ([], False)
    assert c._salvage_json_objects("") == ([], False)


def test_fix_json_escapes_never_mangles_legal_escapes():
    s = r'{"a":"line\nbreak","b":"quote\"","c":"\\u00e9"}'
    assert c._fix_json_escapes(s) == s
    assert json.loads(c._fix_json_escapes(s))["a"] == "line\nbreak"


# === unit: _read_verifier_records + _verifier_parse_alerts ====================

def test_read_verifier_records_counts_unparseable_lines(tmp_path):
    f = tmp_path / "mixed.jsonl"
    f.write_text(
        '{"step":"a"}\n' + LINE_UNESCAPED_QUOTES + "\nnot json at all\n",
        encoding="utf-8")
    recs, bad = c._read_verifier_records(f)
    assert len(recs) == 2
    assert bad == [2]


def test_parse_alerts_fire_for_content_without_verdict(outputs):
    vdir = outputs / "run-x" / "verifier"
    vdir.mkdir(parents=True)
    # file 1: audit records but the VERDICT line is gone (truncated away)
    (vdir / "lost-verdict.jsonl").write_text(
        '{"step":"repro1","http_status":"200"}\n'
        '{"step":"control","http_status":"400"}\n', encoding="utf-8")
    # file 2: healthy
    (vdir / "healthy.jsonl").write_text(
        json.dumps({"step": "VERDICT", "verdict": "CONFIRMED",
                    "ok_to_report": "YES", "claim": "x"}) + "\n", encoding="utf-8")
    # file 3: empty (nothing was ever attempted — no alert)
    (vdir / "empty.jsonl").write_text("", encoding="utf-8")
    alerts = c._verifier_parse_alerts("run-x")
    assert len(alerts) == 1
    assert "lost-verdict.jsonl" in alerts[0]
    assert "NO parseable VERDICT" in alerts[0]


def test_parse_alerts_quiet_when_verdict_salvaged(outputs):
    vdir = outputs / "run-y" / "verifier"
    vdir.mkdir(parents=True)
    (vdir / "salvaged.jsonl").write_text(LINE_UNESCAPED_QUOTES + "\n",
                                         encoding="utf-8")
    assert c._verifier_parse_alerts("run-y") == []


# === integration: the findings chain recovers the audited losses =============

def test_extract_verifier_findings_recovers_lost_confirmed_medium(outputs):
    """The report's §5: a CONFIRMED 4.3 MEDIUM (CWE-209) evaporated because its
    VERDICT line had unescaped quotes in evidence_file. With salvage, the
    extractor must surface it as a verified finding."""
    vdir = outputs / "block-run" / "verifier"
    vdir.mkdir(parents=True)
    (vdir / "get-api-items-page-error-disclosure.jsonl").write_text(
        '{"step":"repro1","http_status":"500"}\n'
        + LINE_UNESCAPED_QUOTES + "\n", encoding="utf-8")
    finds = c._extract_verifier_findings("block-run")
    assert len(finds) == 1
    f = finds[0]
    assert f["verified"] is True
    assert f["cvss"] == 4.3
    assert f["severity"] == "medium"
    assert "CWE-209" in f["cwe_hint"].upper() or "209" in f["title"]


def test_extract_verifier_findings_recovers_concatenated_verdict(outputs):
    """The jwt-logout CONFIRMED 9.1 CRITICAL lost to a missing newline between
    records must reach the extractor as a verified finding."""
    vdir = outputs / "oh-run" / "verifier"
    vdir.mkdir(parents=True)
    (vdir / "jwt-logout-not-invalidated.jsonl").write_text(
        LINE_CONCATENATED + "\n", encoding="utf-8")
    finds = c._extract_verifier_findings("oh-run")
    assert len(finds) == 1
    assert finds[0]["verified"] is True
    assert finds[0]["cvss"] == 9.1


def test_retraction_buckets_survive_salvage(outputs):
    """_retract_contradicted_findings must ingest SALVAGED verdicts too: a
    later NOT_A_VULN written with a trailing `echo` must still retract an
    earlier CONFIRMED verdict in the same defect bucket."""
    vdir = outputs / "run-ret" / "verifier"
    vdir.mkdir(parents=True)
    (vdir / "a-first.jsonl").write_text(json.dumps({
        "step": "VERDICT", "defect": "idor", "verdict": "CONFIRMED",
        "ok_to_report": "YES", "claim": "IDOR on /api/x",
        "route": "GET /api/x", "cvss": "7.5 HIGH"}) + "\n", encoding="utf-8")
    # same defect bucket, WEAKER, later in file order — and serialized with
    # the trailing-garbage defect so it only parses via salvage.
    later = json.dumps({
        "step": "VERDICT", "defect": "idor", "verdict": "NOT_A_VULN",
        "ok_to_report": "NO", "claim": "IDOR on /api/x retest",
        "route": "GET /api/x", "cvss": "0.0 NONE",
        "reason": "control falsifies cross-tenant read",
        "evidence_file": "/outputs/run-ret/verifier/b-later.jsonl"})
    (vdir / "b-later.jsonl").write_text(later + "}echo\n", encoding="utf-8")
    retracted = c._retract_contradicted_findings({"id": "e1"}, "run-ret")
    assert retracted, "salvaged later-weaker verdict must still retract"
    assert any("downgraded" in note for note in retracted.values())


def test_verifier_verdict_for_reads_salvaged_records(outputs):
    run = outputs / "run-v"
    vdir = run / "verifier"
    vdir.mkdir(parents=True)
    (vdir / "slug.jsonl").write_text(LINE_UNESCAPED_QUOTES + "\n",
                                     encoding="utf-8")
    (run / "run.json").write_text("{}", encoding="utf-8")  # meta exists
    verified, line = c._verifier_verdict_for("run-v", "/api/items", "x /api/items")
    assert verified is True
    assert "CONFIRMED" in line
