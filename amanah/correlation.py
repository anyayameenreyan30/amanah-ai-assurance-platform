"""Cross-model threat correlation (the platform's mini-SIEM rule engine).

Reads the unified event log written by every monitor, groups events by the rule's
join key (session, client or IP) and fires when the rule's events occur in order
inside the time window. A fired rule becomes one finding and one incident, routed
by the RACI matrix, instead of several unrelated low-severity alerts.
"""
from __future__ import annotations

import datetime as dt
import json
from collections import defaultdict

from .core import Config, Store, emit_event, home, read_events, record_evidence
from .governance import raise_finding


def _key(event: dict, join_key: str):
    return {"session_id": event["session"]["id"], "client_id": event["client"]["id"],
            "source_ip": event["client"]["ip"]}.get(join_key)


def _ts(event: dict) -> dt.datetime:
    return dt.datetime.fromisoformat(event["@timestamp"])


def correlate(store: Store, cfg: Config) -> list[dict]:
    events = read_events()
    seen_path = home() / "siem" / "correlated.json"
    seen = set(json.loads(seen_path.read_text())) if seen_path.exists() else set()
    fired = []
    for rule in cfg.correlation:
        groups = defaultdict(list)
        for e in events:
            k = _key(e, rule["join_key"])
            if k:
                groups[k].append(e)
        for k, evs in groups.items():
            evs.sort(key=_ts)
            chain, start = [], None
            for step in rule["sequence"]:
                match = next((e for e in evs if e["service"]["name"] == step["system"]
                              and e["event"]["type"] == step["event_type"]
                              and (not chain or _ts(e) >= _ts(chain[-1]))), None)
                if not match:
                    break
                start = start or _ts(match)
                if (_ts(match) - start).total_seconds() > rule["window_seconds"]:
                    break
                chain.append(match)
            if len(chain) != len(rule["sequence"]):
                continue
            sig = f"{rule['id']}:{k}"
            if sig in seen:
                continue
            seen.add(sig)
            systems = sorted({e["service"]["name"] for e in chain})
            detail = {"rule": rule["id"], "join_key": rule["join_key"], "key": k,
                      "systems": systems,
                      "events": [{"ts": e["@timestamp"], "system": e["service"]["name"],
                                  "type": e["event"]["type"], "detail": e["amanah"]} for e in chain],
                      "why": " ".join(rule["description"].split())}
            fid = raise_finding(store, cfg, systems[0], rule["category"], rule["severity"],
                                f"{rule['id']} {rule['name']} ({rule['join_key']}={k})", detail,
                                rule["controls"], rule["owasp"], rule_id=rule["id"])
            emit_event("amanah-correlation", "correlated_attack", rule["severity"],
                       session_id=k if rule["join_key"] == "session_id" else None,
                       client_id=k if rule["join_key"] == "client_id" else None,
                       owasp=rule["owasp"], detail={"rule": rule["id"], "finding": fid})
            fired.append({"rule": rule["id"], "key": k, "finding": fid, "systems": systems})
    seen_path.write_text(json.dumps(sorted(seen)))
    record_evidence(store, "event_log", f"correlation run over {len(events)} events, {len(fired)} rules fired",
                    {"events_scanned": len(events), "fired": fired})
    return fired
