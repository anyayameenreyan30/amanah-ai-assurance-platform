"""Guardrails for the customer support assistant (OWASP LLM01, LLM02, LLM06, LLM07).

The assistant itself is an external LLM behind an API (supplier-assessed under A.10.3).
Amanah sits in front of it as a gateway:

* `score_injection` inspects every user message and retrieved document for prompt
  injection patterns and returns a 0-1 score with the matched techniques.
* Messages scoring >= BLOCK are refused. Messages between FLAG and BLOCK are allowed
  but logged as `prompt_injection_detected`. That middle band is deliberate: blocking
  every borderline message frustrates real customers, so the platform relies on
  cross-system correlation to catch the borderline case that turns into an attack.
* `CustomerDataStore` enforces per-session row baselines on every tool call and logs
  `bulk_data_access` when a session reads far more records than a support chat needs.
* `scan_output` checks responses for card numbers (Luhn-validated) and for leakage
  of the hidden system prompt.
"""
from __future__ import annotations

import base64
import re
from collections import defaultdict

from .core import emit_event

FLAG, BLOCK = 0.35, 0.80

PATTERNS = [
    ("instruction_override", 0.45, r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all)\b.{0,20}\b(instruction|rule|prompt|guideline)s?"),
    ("system_prompt_extraction", 0.45, r"\b(reveal|show|print|repeat|output)\b.{0,30}\b(system prompt|hidden (instructions|prompt)|your (instructions|configuration))"),
    ("role_hijack", 0.30, r"\b(you are now|act as|pretend to be|from now on you)\b"),
    ("privilege_claim", 0.25, r"\b(i am|i'm|as) (an? )?(admin|administrator|developer|auditor|supervisor|internal (staff|team))\b"),
    ("tool_coercion", 0.25, r"\b(call|use|run|invoke)\b.{0,30}\b(tool|function|lookup|export|query)\b"),
    ("bulk_data_request", 0.25, r"\b(all|every|entire|full)\b.{0,25}\b(customers?|accounts?|records?|cardholders?)\b"),
    ("delimiter_injection", 0.30, r"(</?(system|assistant|instructions?)>|\[/?INST\]|###\s*(system|instruction))"),
]
ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def score_injection(text: str) -> dict:
    hits, score = [], 0.0
    low = text.lower()
    for name, weight, pat in PATTERNS:
        if re.search(pat, low, re.S):
            hits.append(name)
            score += weight
    if ZERO_WIDTH.search(text):
        hits.append("hidden_characters")
        score += 0.30
    for blob in B64.findall(text):
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", "ignore").lower()
        except Exception:
            continue
        if any(re.search(p, decoded, re.S) for _, _, p in PATTERNS):
            hits.append("encoded_payload")
            score += 0.40
            break
    return {"score": round(min(score, 1.0), 2), "techniques": hits,
            "action": "block" if score >= BLOCK else "flag" if score >= FLAG else "allow"}


def luhn_ok(num: str) -> bool:
    digits = [int(d) for d in num][::-1]
    total = sum(d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2) for i, d in enumerate(digits))
    return total % 10 == 0


def scan_output(text: str, system_prompt_marker: str = "SYSTEM-PROMPT-v3") -> dict:
    cards = [c for c in re.findall(r"\b\d{13,19}\b", text) if luhn_ok(c)]
    return {"card_numbers": len(cards), "system_prompt_leak": system_prompt_marker in text,
            "safe": not cards and system_prompt_marker not in text}


class CustomerDataStore:
    """Tool backend for the assistant, with per-session access baselines."""

    def __init__(self, rows_threshold: int) -> None:
        self.threshold = rows_threshold
        self.session_rows: dict = defaultdict(int)
        self._alerted: set = set()

    def query(self, session_id: str, rows: int, purpose: str, source_ip: str | None = None) -> int:
        self.session_rows[session_id] += rows
        total = self.session_rows[session_id]
        if total > self.threshold and session_id not in self._alerted:
            self._alerted.add(session_id)
            emit_event("customer-data-store", "bulk_data_access", "medium", session_id=session_id,
                       source_ip=source_ip, owasp=["LLM02", "LLM06"],
                       detail={"rows_in_session": total, "baseline_limit": self.threshold,
                               "purpose": purpose})
        return rows


class SupportAssistantGateway:
    def __init__(self, store: CustomerDataStore) -> None:
        self.store = store
        self.stats = {"messages": 0, "blocked": 0, "flagged": 0}

    def handle(self, session_id: str, message: str, source_ip: str | None = None,
               tool_rows: int = 1) -> dict:
        """Inspect a message; if allowed, the (simulated) assistant may call its lookup tool."""
        self.stats["messages"] += 1
        verdict = score_injection(message)
        if verdict["action"] == "block":
            self.stats["blocked"] += 1
            emit_event("support-llm", "prompt_injection_blocked", "medium", session_id=session_id,
                       source_ip=source_ip, owasp=["LLM01"], detail=verdict)
            return {"blocked": True, **verdict}
        if verdict["action"] == "flag":
            self.stats["flagged"] += 1
            emit_event("support-llm", "prompt_injection_detected", "low", session_id=session_id,
                       source_ip=source_ip, owasp=["LLM01"], detail=verdict)
        if tool_rows:
            self.store.query(session_id, tool_rows, "customer_lookup", source_ip)
        return {"blocked": False, **verdict}
