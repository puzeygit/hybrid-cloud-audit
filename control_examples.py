"""Независимо заданные контрольные примеры и протокол проверки прототипа."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import json
import platform
import statistics
import time
import sqlite3
import tempfile
from audit_core import (RULES, NOW, VERSION, POLICY_VERSION, assess, audit, summary,
                        normalize_export, load_exports, InvalidEvidence, digest,
                        compare, write_reports, save_database)

ROOT = Path(__file__).resolve().parent
BASE = {
    "network": {"ingress": [{"cidr": "10.10.0.0/24", "protocol": "tcp", "port_from": 22, "port_to": 22}]},
    "identity": {"roles": ["reader"]},
    "credential": {"key_created_at": "2026-10-01T12:00:00+00:00"},
    "workload": {"privileged": False, "run_as_non_root": True},
    "namespace": {"default_deny": True, "cni_supports_policy": True},
    "storage": {"classification": "confidential", "public_access": False, "encrypted": True},
    "logging": {"enabled": True, "retention_days": 180},
    "endpoint": {"tls_min_version": "1.2"},
}
# Заранее определенные небезопасные состояния, независимые от программных предикатов.
BAD = {
    "NET-01": {"ingress": [{"cidr": "0.0.0.0/0", "protocol": "tcp", "port_from": 22, "port_to": 22}]},
    "IAM-01": {"roles": ["admin"]},
    "IAM-02": {"key_created_at": "2026-01-01T00:00:00+00:00"},
    "K8S-01": {"privileged": True},
    "K8S-02": {"run_as_non_root": False},
    "K8S-03": {"default_deny": False},
    "STO-01": {"public_access": True},
    "STO-02": {"encrypted": False},
    "LOG-01": {"enabled": False},
    "LOG-02": {"retention_days": 30},
    "TLS-01": {"tls_min_version": "1.0"},
    "DATA-01": {"collected_at": "2026-10-10T12:00:00+00:00"},
}

def create_cases():
    cases = []
    for rule in RULES:
        kind = "network" if rule.kind == "*" else rule.kind
        for state, expected in (("correct", "PASS"), ("deviation", "FAIL"), ("missing", "UNKNOWN")):
            index = len(cases) + 1
            segment = "private" if index % 2 else "public"
            attrs = deepcopy(BASE[kind])
            attrs["collected_at"] = "2026-10-14T11:00:00+00:00"
            if state == "deviation":
                attrs.update(deepcopy(BAD[rule.id]))
                if rule.id == "DATA-01": expected = "UNKNOWN"
            if state == "missing": attrs.pop(rule.fields[0], None)
            resource = {"id": segment + f":CASE-{index:02}", "segment": segment,
                        "kind": kind, "criticality": 2, "attributes": attrs}
            cases.append({"case_id": f"C-{index:02}", "rule_id": rule.id,
                          "state": state, "expected": expected, "resource": resource,
                          "exceptions": []})
    # Форматная ошибка не должна становиться положительным результатом.
    resource = deepcopy(cases[0]["resource"])
    resource["id"] = "private:CASE-37"
    resource["attributes"]["ingress"] = "not-an-array"
    cases.append({"case_id": "C-37", "rule_id": "NET-01", "state": "invalid_type",
                  "expected": "ERROR", "resource": resource, "exceptions": []})
    resource = deepcopy(cases[18]["resource"])
    resource["id"] = "public:CASE-38"; resource["segment"] = "public"
    resource["attributes"]["classification"] = "public"
    resource["attributes"]["public_access"] = True
    cases.append({"case_id": "C-38", "rule_id": "STO-01", "state": "outside_scope",
                  "expected": "NOT_APPLICABLE", "resource": resource, "exceptions": []})
    for index, until, state, exception_expected in (
        (39, "2026-11-01T00:00:00+00:00", "valid_exception", "EX-39"),
        (40, "2026-10-01T00:00:00+00:00", "expired_exception", None)):
        resource = deepcopy(cases[1]["resource"])
        resource["id"] = f"private:CASE-{index}"; resource["segment"] = "private"
        exception = {"id": f"EX-{index}", "resource_id": resource["id"], "rule_id": "NET-01",
                     "approved_by": "model-risk-owner", "status": "approved",
                     "valid_from": "2026-09-01T00:00:00+00:00", "valid_until": until}
        cases.append({"case_id": f"C-{index}", "rule_id": "NET-01", "state": state,
                      "expected": "FAIL", "exception_expected": exception_expected,
                      "resource": resource, "exceptions": [exception]})
    return cases


def export_documents(cases):
    for segment in ("private", "public"):
        rows = []
        for case in cases:
            r = case["resource"]
            if r["segment"] != segment: continue
            rid = r["id"].split(":", 1)[1]
            if segment == "private":
                rows.append({"uuid": rid, "resource_type": r["kind"], "criticality": r["criticality"],
                             "configuration": r["attributes"]})
            else:
                rows.append({"resourceId": rid, "type": r["kind"], "criticality": r["criticality"],
                             "properties": r["attributes"]})
        (ROOT / (segment + ".json")).write_text(json.dumps(
            {"schema_version": "1.0", "source": segment, "resources": rows},
            ensure_ascii=False, indent=2), encoding="utf-8")


def verify(cases):
    rules = {r.id: r for r in RULES}
    protocol = []
    for case in cases:
        result = assess(rules[case["rule_id"]], case["resource"], case["exceptions"], NOW)
        match = result.status == case["expected"]
        if "exception_expected" in case:
            match = match and result.exception_id == case["exception_expected"]
        protocol.append({"case_id": case["case_id"], "rule_id": case["rule_id"], "state": case["state"],
                         "expected": case["expected"], "actual": result.status,
                         "exception_id": result.exception_id, "passed": match, "reason": result.reason})
    if not all(row["passed"] for row in protocol):
        raise AssertionError([row for row in protocol if not row["passed"]])
    return protocol


def integration_checks(records, exceptions=None):
    checks = []
    def record(name, condition):
        checks.append({"name": name, "passed": bool(condition)})
        if not condition: raise AssertionError(name)
    record("two_segments", set(r["segment"] for r in records) == {"private", "public"})
    record("unique_ids", len({r["id"] for r in records}) == 40)
    before = audit(records, exceptions)
    record("deterministic_evidence", [r.evidence_sha256 for r in before] ==
           [r.evidence_sha256 for r in audit(records, exceptions)])
    changed = deepcopy(records)
    target = next(r for r in changed if r["id"] == "public:CASE-02")
    target["attributes"]["ingress"] = deepcopy(BASE["network"]["ingress"])
    after = audit(changed, exceptions)
    delta = compare(before, after)
    record("recheck_transition", any(r["rule_id"] == "NET-01" and r["before"] == "FAIL" and
           r["after"] == "PASS" for r in delta))
    record("empty_coverage_is_undefined", summary([])["determinate_coverage"] is None)
    malformed = {"schema_version": "1.0", "source": "private", "resources": [
        {"uuid": "same", "resource_type": "network", "configuration": {}},
        {"uuid": "same", "resource_type": "network", "configuration": {}}]}
    try:
        normalize_export(malformed); duplicate_rejected = False
    except InvalidEvidence:
        duplicate_rejected = True
    record("duplicate_input_rejected", duplicate_rejected)
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "audit.db"
        save_database(path, "test-run", records, before)
        with sqlite3.connect(path) as db:
            count = db.execute("SELECT count(*) FROM assessments").fetchone()[0]
        record("database_complete", count == 480)
        try:
            save_database(path, "test-run", records, before); collision_rejected = False
        except sqlite3.IntegrityError:
            collision_rejected = True
        record("same_run_not_overwritten", collision_rejected)
    return checks, changed, after, delta


def benchmark(records):
    measures = []
    for copies in (1, 10, 100):
        scaled = []
        for i in range(copies):
            for item in records:
                r = deepcopy(item); r["id"] += f":replica-{i}"; scaled.append(r)
        samples = []
        for rep in range(10):
            start = time.perf_counter_ns(); results = audit(scaled)
            samples.append((time.perf_counter_ns() - start) / 1_000_000)
        measures.append({"resources": len(scaled), "pairs": len(results), "repeats": len(samples),
                         "median_ms": statistics.median(samples), "min_ms": min(samples),
                         "max_ms": max(samples)})
    return measures


def main():
    cases = create_cases(); export_documents(cases)
    protocol = verify(cases)
    records = load_exports([ROOT / "private.json", ROOT / "public.json"])
    exceptions = [e for c in cases for e in c["exceptions"]]
    results = audit(records, exceptions)
    integration, changed, after, delta = integration_checks(records, exceptions)
    write_reports(ROOT / "Результаты", records, results, NOW)
    write_reports(ROOT / "Результаты повторной проверки", changed, after, NOW)
    data = {"engine_version": VERSION, "policy_version": POLICY_VERSION,
            "evaluation_time": NOW.isoformat(), "python": platform.python_version(),
            "os": platform.system(), "architecture": platform.machine(),
            "control_cases": protocol, "integration_checks": integration,
            "benchmark": benchmark(records), "summary": summary(results), "delta": delta,
            "records": records, "cases": cases,
            "rule_catalog": [{"id":r.id,"title":r.title,"kind":r.kind,"severity":r.severity,
                              "requirement":r.requirement,"fields":r.fields,"advice":r.advice} for r in RULES]}
    (ROOT / "protocol.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    (ROOT / "exceptions.json").write_text(json.dumps(exceptions, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"cases_passed": len(protocol), "integration_passed": len(integration),
                      "summary":data["summary"], "benchmark":data["benchmark"]}, ensure_ascii=False, indent=2))

if __name__ == "__main__": main()
