"""Governance workflows: who may do what, who hears about what, and how incidents run.

* authorize()     - least-privilege checks on model weights, training data, findings
                    and production promotion; denials are logged to the SIEM.
* raise_finding() - stores a finding and routes it by the RACI matrix with a due time
                    taken from the escalation policy for its severity.
* signoff()       - named human approval for high-risk changes (Clause 6.3).
* Incident        - contain -> notify -> root cause -> report -> close, each step
                    timestamped and written to the evidence ledger (A.8.4, Clause 10.2).

Notifications are written to AMANAH_HOME/outbox as Markdown messages. Point the
`deliver()` hook at email, Slack or a ticketing API to send them for real.
"""
from __future__ import annotations

import datetime as dt
import json

from .core import Config, Store, emit_event, home, new_id, now, record_evidence


class AccessDenied(PermissionError):
    pass


def authorize(store: Store, cfg: Config, actor_role: str, asset: str, action: str) -> None:
    allowed_roles = cfg.platform["access_control"].get(asset, {}).get(action, [])
    ok = actor_role in allowed_roles
    store.insert("access_log", {"ts": now(), "actor": actor_role, "asset": asset, "action": action,
                                "allowed": int(ok)})
    if not ok:
        emit_event("amanah-platform", "access_denied", "medium", client_id=actor_role,
                   detail={"asset": asset, "action": action})
        raise AccessDenied(f"role '{actor_role}' may not {action} {asset}")


def deliver(notification: dict) -> None:
    """Delivery hook. Default: write a Markdown message to the outbox."""
    path = home() / "outbox" / f"{notification['id']}-{notification['role']}.md"
    path.write_text(f"To: {notification['role_title']} ({notification['raci']})\n"
                    f"Severity: {notification['severity']}  Due by: {notification['due_by']}\n"
                    f"Subject: {notification['subject']}\n\n{notification['body']}\n", encoding="utf-8")


def route(store: Store, cfg: Config, category: str, severity: str, ref_id: str, subject: str,
          body: str) -> list[dict]:
    matrix = cfg.raci["matrix"].get(category, cfg.raci["matrix"]["conformance_gap"])
    esc = cfg.raci["escalation"][severity]
    due = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=esc["notify_within_minutes"])
           ).isoformat(timespec="seconds")
    recipients: dict[str, str] = {}
    for letter in ("R", "A", "C", "I"):
        for role in matrix.get(letter, []):
            recipients.setdefault(role, letter)
    for role in esc["inform"]:
        recipients.setdefault(role, "I (escalation)")
    sent = []
    for role, letter in recipients.items():
        n = {"id": new_id("MSG"), "ts": now(), "role": role, "raci": letter, "ref_id": ref_id,
             "severity": severity, "subject": subject, "body": body, "due_by": due}
        store.insert("notifications", n)
        deliver({**n, "role_title": cfg.raci["roles"].get(role, role)})
        sent.append(n)
    record_evidence(store, "stakeholder_notification",
                    f"{subject}: routed to {len(sent)} roles per RACI ({severity})",
                    {"ref": ref_id, "recipients": recipients, "due_by": due})
    return sent


def raise_finding(store: Store, cfg: Config, system_id: str, category: str, severity: str,
                  title: str, detail: dict, controls: list[str], owasp: list[str] | None = None,
                  rule_id: str | None = None) -> str:
    fid = new_id("F")
    store.insert("findings", {"id": fid, "ts": now(), "system_id": system_id, "category": category,
                              "severity": severity, "title": title, "detail": detail,
                              "controls": ",".join(controls), "owasp": ",".join(owasp or []),
                              "status": "open", "incident_id": None})
    route(store, cfg, category, severity, fid, f"[{severity.upper()}] {title}",
          f"System: {system_id}\nControls: {', '.join(controls)}\nOWASP: {', '.join(owasp or []) or '-'}\n\n"
          + json.dumps(detail, indent=2, default=str)[:3000])
    if cfg.raci["escalation"][severity]["open_incident"] and category not in ("robustness_failure", "fairness_issue", "conformance_gap"):
        Incident.open(store, cfg, system_id, severity, title, [fid], rule_id=rule_id)
    return fid


# ------------------------------------------------------------------ sign-off
def required_signoffs(cfg: Config, system_id: str) -> list[str]:
    s = cfg.system(system_id)
    roles = []
    if s["decision_criticality"] == "high":
        roles += cfg.raci["signoff_rules"]["high_risk_change"]
    if s["personal_data"]:
        roles += cfg.raci["signoff_rules"]["personal_data_change"]
    return sorted(set(roles))


def signoff(store: Store, cfg: Config, change_id: str, system_id: str, role: str, approver: str,
            decision: str = "approved", note: str = "") -> str:
    authorize(store, cfg, role, "signoff", "write")
    sid = new_id("SO")
    store.insert("signoffs", {"id": sid, "change_id": change_id, "system_id": system_id, "role": role,
                              "approver": approver, "decision": decision, "ts": now(), "note": note})
    record_evidence(store, "signoff_record", f"{role} {decision} change {change_id} ({approver})",
                    {"change": change_id, "role": role, "approver": approver, "decision": decision,
                     "note": note}, system_id=system_id, result=decision)
    return sid


def signoffs_for(store: Store, change_id: str) -> list[str]:
    return [r["role"] for r in store.rows(
        "SELECT role FROM signoffs WHERE change_id=? AND decision='approved'", [change_id])]


# ------------------------------------------------------------------ incidents
class Incident:
    STATES = ["detected", "contained", "notified", "root_cause", "reported", "closed"]

    @staticmethod
    def open(store: Store, cfg: Config, system_id: str, severity: str, title: str,
             findings: list[str], rule_id: str | None = None) -> str:
        iid = new_id("INC")
        store.insert("incidents", {"id": iid, "opened_at": now(), "system_id": system_id,
                                   "severity": severity, "title": title, "state": "detected",
                                   "rule_id": rule_id, "findings": findings,
                                   "timeline": [{"ts": now(), "state": "detected", "note": title}],
                                   "root_cause": None, "corrective_action": None, "closed_at": None})
        for f in findings:
            store.update("findings", "id", f, incident_id=iid)
        record_evidence(store, "incident_record", f"incident {iid} opened: {title}",
                        {"incident": iid, "severity": severity, "findings": findings, "rule": rule_id},
                        system_id=system_id)
        return iid

    @staticmethod
    def advance(store: Store, iid: str, state: str, note: str, **fields) -> None:
        inc = store.one("SELECT * FROM incidents WHERE id=?", [iid])
        timeline = json.loads(inc["timeline"])
        timeline.append({"ts": now(), "state": state, "note": note})
        extra = {"closed_at": now()} if state == "closed" else {}
        store.update("incidents", "id", iid, state=state, timeline=timeline, **fields, **extra)
        etype = {"notified": "incident_record", "root_cause": "corrective_action",
                 "reported": "incident_record", "closed": "corrective_action"}.get(state, "incident_record")
        record_evidence(store, etype, f"incident {iid} -> {state}: {note}",
                        {"incident": iid, "state": state, "note": note, **fields},
                        system_id=inc["system_id"])

    @staticmethod
    def open_critical(store: Store, system_id: str) -> list[str]:
        return [r["id"] for r in store.rows(
            "SELECT id FROM incidents WHERE system_id=? AND severity='critical' AND state!='closed'",
            [system_id])]
