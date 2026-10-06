"""Core services: configuration, storage, the evidence ledger and the security event log.

The evidence ledger is hash-chained: every entry stores the hash of the entry before
it, so editing or deleting any past record breaks the chain and `verify_chain()`
reports exactly where. This is what lets an auditor trust automatically collected
evidence (Clause 7.5, documented information).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Iterable

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = Path(os.environ.get("AMANAH_CONFIG", PROJECT_ROOT / "config"))
POLICY_DIR = PROJECT_ROOT / "policies"


def home() -> Path:
    """Working directory for the database, keys, registry, logs and reports."""
    p = Path(os.environ.get("AMANAH_HOME", PROJECT_ROOT / "var"))
    p.mkdir(parents=True, exist_ok=True)
    for sub in ("keys", "registry", "data", "siem", "outbox", "reports", "evidence"):
        (p / sub).mkdir(exist_ok=True)
    return p


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def load_yaml(name: str) -> dict:
    with open(CONFIG_DIR / name, encoding="utf-8") as f:
        return yaml.safe_load(f)


class Config:
    def __init__(self) -> None:
        self.platform = load_yaml("platform.yaml")
        self.iso = load_yaml("iso42001.yaml")
        self.threats = load_yaml("threats.yaml")["threats"]
        self.raci = load_yaml("raci.yaml")
        self.correlation = load_yaml("correlation_rules.yaml")["rules"]

    @property
    def thresholds(self) -> dict:
        return self.platform["thresholds"]

    @property
    def runtime(self) -> dict:
        return self.platform["runtime"]

    def system(self, system_id: str) -> dict:
        for s in self.platform["ai_systems"]:
            if s["id"] == system_id:
                return s
        raise KeyError(f"unknown AI system '{system_id}'")

    def annex_controls(self) -> list[dict]:
        out = []
        for obj in self.iso["annex_a"]:
            for c in obj["controls"]:
                out.append({**c, "objective": obj["objective"], "objective_title": obj["title"]})
        return out


SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE, ts TEXT, type TEXT, system_id TEXT,
  summary TEXT, result TEXT, payload TEXT, payload_sha256 TEXT, prev_hash TEXT, entry_hash TEXT);
CREATE TABLE IF NOT EXISTS risks (
  id TEXT PRIMARY KEY, system_id TEXT, threat_id TEXT, name TEXT, owasp TEXT, likelihood INTEGER,
  impact INTEGER, score INTEGER, level TEXT, rationale TEXT, controls TEXT, treatment TEXT,
  residual_score INTEGER, status TEXT, source TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, ts TEXT, system_id TEXT, category TEXT, severity TEXT, title TEXT,
  detail TEXT, controls TEXT, owasp TEXT, status TEXT, incident_id TEXT);
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY, opened_at TEXT, system_id TEXT, severity TEXT, title TEXT, state TEXT,
  rule_id TEXT, findings TEXT, timeline TEXT, root_cause TEXT, corrective_action TEXT, closed_at TEXT);
CREATE TABLE IF NOT EXISTS signoffs (
  id TEXT PRIMARY KEY, change_id TEXT, system_id TEXT, role TEXT, approver TEXT, decision TEXT,
  ts TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS models (
  id TEXT PRIMARY KEY, system_id TEXT, version INTEGER, path TEXT, sha256 TEXT, signature TEXT,
  stage TEXT, metrics TEXT, created_at TEXT, promoted_at TEXT, change_id TEXT);
CREATE TABLE IF NOT EXISTS pipeline_runs (
  id TEXT PRIMARY KEY, system_id TEXT, started TEXT, finished TEXT, status TEXT, stages TEXT,
  gate TEXT, model_id TEXT, label TEXT);
CREATE TABLE IF NOT EXISTS impact_assessments (
  id TEXT PRIMARY KEY, system_id TEXT, status TEXT, content TEXT, ts TEXT, approver TEXT);
CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY, ts TEXT, role TEXT, raci TEXT, ref_id TEXT, severity TEXT, subject TEXT,
  body TEXT, due_by TEXT);
CREATE TABLE IF NOT EXISTS access_log (
  ts TEXT, actor TEXT, asset TEXT, action TEXT, allowed INTEGER);
"""


class Store:
    """Thin SQLite wrapper. Swap the connection string for PostgreSQL in production."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or home() / "amanah.db"
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def insert(self, table: str, row: dict) -> None:
        cols = ",".join(row)
        qs = ",".join("?" for _ in row)
        vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in row.values()]
        self.conn.execute(f"INSERT OR REPLACE INTO {table} ({cols}) VALUES ({qs})", vals)
        self.conn.commit()

    def update(self, table: str, key: str, key_val: Any, **fields: Any) -> None:
        sets = ",".join(f"{k}=?" for k in fields)
        vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in fields.values()]
        self.conn.execute(f"UPDATE {table} SET {sets} WHERE {key}=?", [*vals, key_val])
        self.conn.commit()

    def rows(self, sql: str, params: Iterable = ()) -> list[dict]:
        return [dict(r) for r in self.conn.execute(sql, tuple(params))]

    def one(self, sql: str, params: Iterable = ()) -> dict | None:
        r = self.conn.execute(sql, tuple(params)).fetchone()
        return dict(r) if r else None


# ---------------------------------------------------------------- evidence ledger
GENESIS = "0" * 64


def _entry_hash(prev_hash: str, ts: str, etype: str, system_id: str, summary: str,
                result: str, payload_sha: str) -> str:
    material = "|".join([prev_hash, ts, etype, system_id or "", summary, result or "", payload_sha])
    return hashlib.sha256(material.encode()).hexdigest()


def record_evidence(store: Store, etype: str, summary: str, payload: dict | None = None,
                    system_id: str | None = None, result: str = "recorded") -> str:
    """Append one evidence entry to the hash chain and save its payload as a JSON file."""
    payload = payload or {}
    eid = new_id("EV")
    ts = now()
    blob = json.dumps(payload, indent=2, sort_keys=True, default=str)
    payload_sha = hashlib.sha256(blob.encode()).hexdigest()
    (home() / "evidence" / f"{eid}.json").write_text(blob, encoding="utf-8")
    last = store.one("SELECT entry_hash FROM evidence ORDER BY seq DESC LIMIT 1")
    prev = last["entry_hash"] if last else GENESIS
    h = _entry_hash(prev, ts, etype, system_id, summary, result, payload_sha)
    store.insert("evidence", {"id": eid, "ts": ts, "type": etype, "system_id": system_id,
                              "summary": summary, "result": result, "payload": f"evidence/{eid}.json",
                              "payload_sha256": payload_sha, "prev_hash": prev, "entry_hash": h})
    return eid


def verify_chain(store: Store) -> dict:
    """Recompute every hash. Detects edited rows, deleted rows and edited payload files."""
    prev = GENESIS
    problems = []
    entries = store.rows("SELECT * FROM evidence ORDER BY seq")
    for e in entries:
        payload_file = home() / e["payload"]
        actual_sha = (hashlib.sha256(payload_file.read_bytes()).hexdigest()
                      if payload_file.exists() else "missing")
        if actual_sha != e["payload_sha256"]:
            problems.append(f"{e['id']}: payload file altered or missing")
        if e["prev_hash"] != prev:
            problems.append(f"{e['id']}: chain broken (an earlier entry was removed or changed)")
        expect = _entry_hash(e["prev_hash"], e["ts"], e["type"], e["system_id"], e["summary"],
                             e["result"], e["payload_sha256"])
        if expect != e["entry_hash"]:
            problems.append(f"{e['id']}: entry contents altered")
        prev = e["entry_hash"]
    return {"entries": len(entries), "intact": not problems, "problems": problems,
            "head": prev}


# ---------------------------------------------------------------- SIEM event log
def emit_event(system_id: str, event_type: str, severity: str = "info", *,
               session_id: str | None = None, client_id: str | None = None,
               source_ip: str | None = None, owasp: list[str] | None = None,
               detail: dict | None = None, ts: str | None = None) -> dict:
    """Write one security event to the unified log (JSON lines, ECS-style field names).

    Any SIEM (Elastic, Splunk, Wazuh, Sentinel) can tail this file with its standard
    file shipper; the correlation engine reads the same file.
    """
    event = {
        "@timestamp": ts or now(),
        "event": {"id": new_id("EVT"), "kind": "alert" if severity != "info" else "event",
                  "type": event_type, "severity": severity, "module": "amanah"},
        "service": {"name": system_id},
        "session": {"id": session_id}, "client": {"id": client_id, "ip": source_ip},
        "threat": {"owasp": owasp or []},
        "amanah": detail or {},
    }
    with open(home() / "siem" / "events.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(event, default=str) + "\n")
    return event


def read_events() -> list[dict]:
    path = home() / "siem" / "events.jsonl"
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
