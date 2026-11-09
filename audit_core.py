"""Учебный механизм аудита модельных облачных выгрузок. Не подключается к X5."""
from __future__ import annotations
import argparse
import csv
import hashlib
import html
import ipaddress
import json
import sqlite3
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

VERSION = "1.0.1"
POLICY_VERSION = "POL-2026-01"
STATUSES = ("PASS", "FAIL", "UNKNOWN", "ERROR", "NOT_APPLICABLE")
LABELS = {"PASS": "Соответствует", "FAIL": "Нарушение", "UNKNOWN": "Недостаточно данных",
          "ERROR": "Ошибка обработки", "NOT_APPLICABLE": "Не применимо"}
NOW = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)

class MissingEvidence(Exception):
    """Обязательное свидетельство отсутствует."""

class InvalidEvidence(Exception):
    """Свидетельство имеет недопустимый формат или тип."""

@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    kind: str
    severity: int
    requirement: str
    fields: tuple[str, ...]
    advice: str
    checker: Callable[[dict, datetime], tuple[bool, str]]

@dataclass(frozen=True)
class Result:
    resource_id: str
    segment: str
    kind: str
    rule_id: str
    requirement: str
    status: str
    severity: int
    priority: int
    reason: str
    evidence: dict
    evidence_sha256: str
    exception_id: str | None
    policy_version: str


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def field(record: dict, name: str, kind: type) -> Any:
    attrs = record.get("attributes", {})
    if not isinstance(attrs, dict):
        raise InvalidEvidence("attributes должен быть объектом")
    if name not in attrs or attrs[name] is None:
        raise MissingEvidence("Нет поля " + name)
    value = attrs[name]
    if type(value) is not kind:
        raise InvalidEvidence(f"Поле {name}: нужен тип {kind.__name__}")
    return value


def moment(value: Any) -> datetime:
    if not isinstance(value, str):
        raise InvalidEvidence("Время должно быть строкой ISO 8601")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidEvidence("Неверная временная метка") from exc
    if parsed.tzinfo is None:
        raise InvalidEvidence("Не указан часовой пояс")
    return parsed.astimezone(timezone.utc)


def check_network(r: dict, now: datetime) -> tuple[bool, str]:
    rules = field(r, "ingress", list)
    for item in rules:
        if not isinstance(item, dict):
            raise InvalidEvidence("Сетевое правило должно быть объектом")
        try:
            cidr = ipaddress.ip_network(item["cidr"], strict=False)
            low, high = item["port_from"], item["port_to"]
            protocol = item["protocol"]
        except (KeyError, ValueError, TypeError) as exc:
            raise InvalidEvidence("Неверное сетевое правило") from exc
        if type(low) is not int or type(high) is not int or not 0 <= low <= high <= 65535:
            raise InvalidEvidence("Неверный диапазон портов")
        if not isinstance(protocol, str) or protocol.lower() not in {"tcp", "udp", "icmp", "icmpv6", "all"}:
            raise InvalidEvidence("Неизвестный протокол в учебной схеме")
        if cidr.prefixlen == 0 and protocol.lower() in ("tcp", "all"):
            if any(low <= port <= high for port in (22, 3389)):
                return False, "Административный порт доступен из любой сети"
    return True, "Нет разрешения административного доступа из любой сети"


def check_iam(r: dict, now: datetime) -> tuple[bool, str]:
    roles = field(r, "roles", list)
    if not all(isinstance(role, str) for role in roles):
        raise InvalidEvidence("roles содержит нестроковое значение")
    ok = not any(role in {"admin", "cluster-admin", "*"} for role in roles)
    return ok, "Проверены избыточные административные назначения"


def check_key(r: dict, now: datetime) -> tuple[bool, str]:
    issued = moment(field(r, "key_created_at", str))
    age = (now - issued).total_seconds() / 86400
    if age < 0:
        raise InvalidEvidence("Ключ создан в будущем")
    return age <= 90, f"Возраст ключа {age:.2f} суток; проектный предел 90"


def boolean_rule(name: str, wanted: bool) -> Callable:
    def evaluate(r: dict, now: datetime) -> tuple[bool, str]:
        value = field(r, name, bool)
        return value is wanted, f"{name}={value}; требуется {wanted}"
    return evaluate


def check_policies(r: dict, now: datetime) -> tuple[bool, str]:
    supports = field(r, "cni_supports_policy", bool)
    default_deny = field(r, "default_deny", bool)
    return supports and default_deny, "Проверены поддержка политик CNI и default-deny"


def check_public(r: dict, now: datetime) -> tuple[bool, str]:
    public = field(r, "public_access", bool)
    return not public, "Публичный доступ к конфиденциальному хранилищу запрещен"


def check_retention(r: dict, now: datetime) -> tuple[bool, str]:
    days = field(r, "retention_days", int)
    if days < 0:
        raise InvalidEvidence("Срок хранения отрицательный")
    return days >= 180, f"retention_days={days}; проектный минимум 180"


def check_tls(r: dict, now: datetime) -> tuple[bool, str]:
    value = field(r, "tls_min_version", str)
    try:
        parts = tuple(int(part) for part in value.split("."))
    except ValueError as exc:
        raise InvalidEvidence("Неверная версия TLS") from exc
    if len(parts) != 2 or parts[0] != 1 or parts[1] not in (0, 1, 2, 3):
        raise InvalidEvidence("Неизвестная версия TLS")
    return parts >= (1, 2), "Минимальная проектная версия TLS 1.2"


def check_freshness(r: dict, now: datetime) -> tuple[bool, str]:
    value = field(r, "collected_at", str)
    age = (now - moment(value)).total_seconds() / 3600
    if age < 0:
        raise InvalidEvidence("Снимок датирован будущим")
    if age > 24:
        raise MissingEvidence("Свидетельство старше проектного предела 24 часа")
    return True, f"Возраст свидетельства {age:.2f} часов"


RULES = (
    Rule("NET-01", "Административные порты", "network", 3, "F-03", ("ingress",),
         "Ограничить доступ утвержденными административными сетями", check_network),
    Rule("IAM-01", "Избыточные привилегии", "identity", 3, "F-04", ("roles",),
         "Пересмотреть назначение административных ролей", check_iam),
    Rule("IAM-02", "Возраст сервисного ключа", "credential", 2, "F-04", ("key_created_at",),
         "Выполнить ротацию ключа с учетом зависимости сервисов", check_key),
    Rule("K8S-01", "Привилегированный контейнер", "workload", 3, "F-05", ("privileged",),
         "Отказаться от privileged при отсутствии согласованной необходимости",
         boolean_rule("privileged", False)),
    Rule("K8S-02", "Запуск от непривилегированного пользователя", "workload", 2, "F-05",
         ("run_as_non_root",), "Использовать runAsNonRoot и совместимый образ",
         boolean_rule("run_as_non_root", True)),
    Rule("K8S-03", "Сетевая изоляция namespace", "namespace", 2, "F-05",
         ("cni_supports_policy", "default_deny"), "Проверить CNI и политику default-deny", check_policies),
    Rule("STO-01", "Публичность хранилища", "storage", 3, "F-06", ("public_access",),
         "Закрыть публичный доступ к конфиденциальным объектам", check_public),
    Rule("STO-02", "Шифрование при хранении", "storage", 2, "F-06", ("encrypted",),
         "Включить шифрование и отдельно проверить управление ключами",
         boolean_rule("encrypted", True)),
    Rule("LOG-01", "Журналирование действий", "logging", 2, "F-07", ("enabled",),
         "Включить согласованный профиль регистрации событий", boolean_rule("enabled", True)),
    Rule("LOG-02", "Срок хранения событий", "logging", 1, "F-07", ("retention_days",),
         "Согласовать и обеспечить проектный срок хранения", check_retention),
    Rule("TLS-01", "Защита интерфейса", "endpoint", 2, "F-08", ("tls_min_version",),
         "Ограничить интерфейс версиями TLS 1.2 и выше", check_tls),
    Rule("DATA-01", "Актуальность свидетельства", "*", 1, "F-02", ("collected_at",),
         "Повторно собрать данные; не подменять неизвестное соответствием", check_freshness),
)


def applicable(rule: Rule, r: dict) -> bool:
    if rule.kind not in ("*", r.get("kind")):
        return False
    if rule.id == "STO-01":
        classification = field(r, "classification", str)
        if classification not in ("public", "internal", "confidential"):
            raise InvalidEvidence("Неизвестная классификация данных")
        return classification == "confidential"
    return True


def valid_exception(exceptions: list, r: dict, rule: Rule, now: datetime) -> str | None:
    for exc in exceptions:
        if not isinstance(exc, dict):
            continue
        if exc.get("resource_id") != r.get("id") or exc.get("rule_id") != rule.id:
            continue
        if not exc.get("approved_by") or exc.get("status") != "approved":
            continue
        try:
            if moment(exc["valid_from"]) <= now < moment(exc["valid_until"]):
                return str(exc["id"])
        except (KeyError, InvalidEvidence):
            continue
    return None


def assess(rule: Rule, r: dict, exceptions: list, now: datetime) -> Result:
    status, reason = "NOT_APPLICABLE", "Тип ресурса вне области правила"
    attrs = r.get("attributes", {})
    evidence = {key: attrs.get(key) for key in (*rule.fields, "collected_at")} if isinstance(attrs, dict) else {}
    if rule.id == "STO-01":
        evidence["classification"] = attrs.get("classification") if isinstance(attrs, dict) else None
    try:
        if applicable(rule, r):
            if r.get("collection_error"):
                raise InvalidEvidence("Ошибка сбора: " + str(r["collection_error"]))
            if rule.id != "DATA-01":
                check_freshness(r, now)
            ok, reason = rule.checker(r, now)
            status = "PASS" if ok else "FAIL"
    except MissingEvidence as exc:
        status, reason = "UNKNOWN", str(exc)
    except InvalidEvidence as exc:
        status, reason = "ERROR", str(exc)
    exception_id = valid_exception(exceptions, r, rule, now) if status == "FAIL" else None
    criticality = r.get("criticality", 1)
    if type(criticality) is not int or criticality not in (1, 2, 3):
        criticality = 1
    priority = rule.severity * criticality if status == "FAIL" else 0
    return Result(str(r["id"]), str(r["segment"]), str(r["kind"]), rule.id,
                  rule.requirement, status, rule.severity, priority, reason,
                  evidence, digest(evidence), exception_id, POLICY_VERSION)


def normalize_export(document: dict) -> list[dict]:
    if document.get("schema_version") != "1.0":
        raise InvalidEvidence("Не поддерживается schema_version")
    source = document.get("source")
    if source not in ("private", "public"):
        raise InvalidEvidence("Нужен сегмент private или public")
    items = document.get("resources")
    if not isinstance(items, list):
        raise InvalidEvidence("resources должен быть массивом")
    normalized = []
    ids = set()
    for item in items:
        if not isinstance(item, dict):
            raise InvalidEvidence("Ресурс должен быть объектом")
        if source == "private":
            identifier, kind = item.get("uuid"), item.get("resource_type")
            attrs = item.get("configuration")
            error = item.get("collection_error")
        else:
            identifier, kind = item.get("resourceId"), item.get("type")
            attrs = item.get("properties")
            error = item.get("collectionError")
        if not isinstance(identifier, str) or not identifier:
            raise InvalidEvidence("Пустой идентификатор ресурса")
        rid = source + ":" + identifier
        if rid in ids:
            raise InvalidEvidence("Повтор идентификатора в одном снимке")
        if kind not in {"network", "identity", "credential", "workload", "namespace",
                         "storage", "logging", "endpoint"}:
            raise InvalidEvidence("Неизвестный тип ресурса")
        if not isinstance(attrs, dict):
            raise InvalidEvidence("Конфигурация должна быть объектом")
        ids.add(rid)
        normalized.append({"id": rid, "kind": kind, "segment": source,
                           "criticality": item.get("criticality", 2),
                           "attributes": attrs, "collection_error": error})
    return normalized


def load_exports(paths: list[Path]) -> list[dict]:
    all_records = []
    for path in paths:
        with path.open(encoding="utf-8") as stream:
            value = json.load(stream)
        if not isinstance(value, dict):
            raise InvalidEvidence("Верхний уровень выгрузки должен быть объектом")
        all_records.extend(normalize_export(value))
    if len({r["id"] for r in all_records}) != len(all_records):
        raise InvalidEvidence("Несколько снимков одного ресурса требуют явного выбора")
    return all_records


def audit(records: list[dict], exceptions: list | None = None,
          now: datetime = NOW) -> list[Result]:
    return [assess(rule, record, exceptions or [], now)
            for record in records for rule in RULES]


def summary(results: list[Result]) -> dict:
    counts = Counter(r.status for r in results)
    applicable_count = len(results) - counts["NOT_APPLICABLE"]
    determinate = counts["PASS"] + counts["FAIL"]
    return {"total_pairs": len(results), "applicable_pairs": applicable_count,
            "counts": {s: counts[s] for s in STATUSES},
            "determinate_coverage": determinate / applicable_count if applicable_count else None,
            "pass_share_determinate": counts["PASS"] / determinate if determinate else None,
            "failures_with_exception": sum(bool(r.exception_id) for r in results)}


def compare(before: list[Result], after: list[Result]) -> list[dict]:
    old = {(r.resource_id, r.rule_id): r for r in before}
    new = {(r.resource_id, r.rule_id): r for r in after}
    changes = []
    for key in sorted(old.keys() | new.keys()):
        a, b = old.get(key), new.get(key)
        if not a or not b or a.status != b.status or a.evidence_sha256 != b.evidence_sha256:
            changes.append({"resource_id": key[0], "rule_id": key[1],
                            "before": a.status if a else "ABSENT",
                            "after": b.status if b else "ABSENT",
                            "evidence_changed": bool(a and b and a.evidence_sha256 != b.evidence_sha256)})
    return changes


def save_database(path: Path, run_id: str, records: list[dict], results: list[Result]) -> None:
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA foreign_keys=ON")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS runs(
            id TEXT PRIMARY KEY, engine_version TEXT NOT NULL,
            policy_version TEXT NOT NULL, input_hash TEXT NOT NULL,
            resource_count INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS resources(
            run_id TEXT NOT NULL REFERENCES runs(id), resource_id TEXT NOT NULL,
            segment TEXT NOT NULL, kind TEXT NOT NULL,
            PRIMARY KEY(run_id,resource_id));
        CREATE TABLE IF NOT EXISTS assessments(
            run_id TEXT NOT NULL, resource_id TEXT NOT NULL, rule_id TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('PASS','FAIL','UNKNOWN','ERROR','NOT_APPLICABLE')),
            priority INTEGER NOT NULL, evidence_hash TEXT NOT NULL,
            payload TEXT NOT NULL, PRIMARY KEY(run_id,resource_id,rule_id),
            FOREIGN KEY(run_id,resource_id) REFERENCES resources(run_id,resource_id));
        """)
        db.execute("INSERT INTO runs VALUES(?,?,?,?,?)", (run_id, VERSION, POLICY_VERSION,
                                                       digest(records), len(records)))
        for r in records:
            db.execute("INSERT INTO resources VALUES(?,?,?,?)", (run_id, r["id"], r["segment"], r["kind"]))
        for r in results:
            db.execute("INSERT INTO assessments VALUES(?,?,?,?,?,?,?)",
                       (run_id, r.resource_id, r.rule_id, r.status, r.priority,
                        r.evidence_sha256, canonical(asdict(r)).decode()))


def write_reports(folder: Path, records: list[dict], results: list[Result], now: datetime) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    data = {"engine_version": VERSION, "policy_version": POLICY_VERSION,
            "evaluation_time": now.isoformat(), "input_sha256": digest(records),
            "summary": summary(results), "results": [asdict(r) for r in results]}
    (folder / "audit.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    with (folder / "audit.csv").open("w", encoding="utf-8", newline="") as stream:
        columns = ("resource_id", "segment", "rule_id", "status", "priority", "exception_id", "reason")
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for r in results:
            writer.writerow({k: asdict(r)[k] for k in columns})
    relevant = [r for r in results if r.status != "NOT_APPLICABLE"]
    rows = []
    for r in sorted(relevant, key=lambda x: (-x.priority, x.resource_id, x.rule_id)):
        cells = (r.resource_id, r.segment, r.rule_id, LABELS[r.status],
                 r.priority, r.exception_id or "–", r.reason)
        rows.append("<tr>" + "".join("<td>" + html.escape(str(v)) + "</td>" for v in cells) + "</tr>")
    stats = html.escape(json.dumps(summary(results), ensure_ascii=False))
    page = ('<!doctype html><html lang="ru"><meta charset="utf-8"><title>Отчет аудита</title>'
            '<style>body{font:15px system-ui;margin:30px;color:#111}table{border-collapse:collapse;width:100%}'
            'td,th{border:1px solid #aaa;padding:7px;text-align:left}th{background:#eee}</style>'
            '<h1>Отчет аудита модельной инфраструктуры</h1>'
            '<p>Учебные данные. Связь с реальной инфраструктурой X5 отсутствует.</p>'
            '<h2>Сводка</h2><pre>' + stats + '</pre>'
            '<h2>Результаты</h2><table><tr><th>Ресурс</th><th>Сегмент</th><th>Правило</th>'
            '<th>Статус</th><th>Приоритет</th><th>Исключение</th><th>Основание</th></tr>'
            + ''.join(rows) + '</table></html>')
    (folder / "audit.html").write_text(page, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Аудит учебных выгрузок гибридного облака")
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, default=Path("results"))
    parser.add_argument("--exceptions", type=Path)
    parser.add_argument("--now", default=NOW.isoformat())
    parser.add_argument("--database", type=Path)
    args = parser.parse_args()
    try:
        records = load_exports(args.inputs)
        exceptions = json.loads(args.exceptions.read_text(encoding="utf-8")) if args.exceptions else []
        if not isinstance(exceptions, list):
            raise InvalidEvidence("Исключения должны быть массивом")
        now = moment(args.now)
        results = audit(records, exceptions, now)
        write_reports(args.output, records, results, now)
        if args.database:
            run_id = digest({"input": records, "policy": POLICY_VERSION, "now": now.isoformat()})
            save_database(args.database, run_id, records, results)
        print(json.dumps(summary(results), ensure_ascii=False, indent=2))
        return 0
    except (OSError, json.JSONDecodeError, InvalidEvidence, sqlite3.Error) as exc:
        print("Ошибка: " + str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
