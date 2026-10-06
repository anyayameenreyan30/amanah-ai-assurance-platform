"""Self-contained HTML dashboard, regenerated from the database on every run.

Every number is computed from the evidence ledger and the platform's tables.
The file has no external dependencies apart from optional web fonts, so it can be
opened offline, attached to an audit pack, or published as a link.
"""
from __future__ import annotations

import html
import json
import re
from collections import Counter

from .compliance import conformance
from .core import Config, Store, home, now, read_events, verify_chain

E = html.escape


def _robustness_series(store: Store) -> list[dict]:
    out = []
    for ev in store.rows("SELECT * FROM evidence WHERE type='robustness_test' ORDER BY seq"):
        payload = json.loads((home() / ev["payload"]).read_text())
        m = re.match(r"v(\d+):", ev["summary"])
        out.append({"version": int(m.group(1)) if m else 0, "result": ev["result"],
                    "points": [(c["epsilon"], c["pgd_evasion_success_rate"]) for c in payload["curve"]]})
    return out


def _chart(series: list[dict], gate_eps: float, max_evasion: float) -> str:
    w, h, pl, pb, pt, pr = 560, 280, 56, 44, 16, 120
    xs = sorted({p[0] for s in series for p in s["points"]}) or [0.05, 0.1, 0.15]
    xmin, xmax = 0.0, max(xs) + 0.02

    def X(v):
        return pl + (v - xmin) / (xmax - xmin) * (w - pl - pr)

    def Y(v):
        return pt + (1 - v) * (h - pt - pb)

    parts = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="Evasion success rate by attack strength for each model version">']
    for t in (0, .25, .5, .75, 1):
        parts.append(f'<line x1="{pl}" x2="{w - pr}" y1="{Y(t):.1f}" y2="{Y(t):.1f}" class="grid"/>'
                     f'<text x="{pl - 8}" y="{Y(t) + 4:.1f}" class="ax" text-anchor="end">{int(t * 100)}%</text>')
    for v in xs:
        parts.append(f'<text x="{X(v):.1f}" y="{h - pb + 20}" class="ax" text-anchor="middle">{v:.2f}</text>')
    parts.append(f'<text x="{(pl + w - pr) / 2:.0f}" y="{h - 6}" class="ax" text-anchor="middle">Attack strength (epsilon)</text>')
    parts.append(f'<line x1="{X(gate_eps):.1f}" x2="{X(gate_eps):.1f}" y1="{pt}" y2="{h - pb}" class="gate"/>'
                 f'<line x1="{pl}" x2="{w - pr}" y1="{Y(max_evasion):.1f}" y2="{Y(max_evasion):.1f}" class="limit"/>'
                 f'<text x="{w - pr + 6}" y="{Y(max_evasion) + 4:.1f}" class="ax">limit {int(max_evasion * 100)}%</text>')
    for s in series:
        cls = "s-pass" if s["result"] == "pass" else "s-fail"
        pts = " ".join(f"{X(a):.1f},{Y(b):.1f}" for a, b in s["points"])
        parts.append(f'<polyline points="{pts}" class="{cls}"/>')
        for a, b in s["points"]:
            parts.append(f'<circle cx="{X(a):.1f}" cy="{Y(b):.1f}" r="4" class="{cls}"><title>v{s["version"]}: '
                         f'{b:.0%} evaded at epsilon {a}</title></circle>')
        la, lb = s["points"][-1]
        parts.append(f'<text x="{X(la) + 10:.1f}" y="{Y(lb) + 4:.1f}" class="lbl {cls}">v{s["version"]} '
                     f'{"hardened" if s["result"] == "pass" else "standard"}</text>')
    parts.append("</svg>")
    return "".join(parts)


def build(store: Store, cfg: Config) -> str:
    conf = conformance(store, cfg)
    chain = verify_chain(store)
    t = cfg.thresholds
    s = conf["annex_summary"]
    runs = store.rows("SELECT * FROM pipeline_runs ORDER BY started")
    incidents = store.rows("SELECT * FROM incidents ORDER BY opened_at")
    risks = store.rows("SELECT * FROM risks ORDER BY CASE WHEN system_id='AIMS' THEN 1 ELSE 0 END, score DESC")
    events = read_events()
    ev_counts = Counter((e["service"]["name"], e["event"]["type"]) for e in events)
    ledger_tail = store.rows("SELECT * FROM evidence ORDER BY seq DESC LIMIT 10")
    notifications = store.rows("SELECT role, COUNT(*) n FROM notifications GROUP BY role ORDER BY n DESC")

    # --- control map
    groups = []
    for obj in cfg.iso["annex_a"]:
        tiles = []
        for c in [c for c in conf["controls"] if c["objective"] == obj["objective"]]:
            detail = {"id": c["id"], "title": c["title"], "status": c["status"], "evidence": c["evidence"],
                      "missing": c["missing"], "count": c["evidence_count"]}
            tiles.append(f'<button class="tile st-{c["status"]}" data-c=\'{E(json.dumps(detail))}\' '
                         f'aria-label="{E(c["id"])} {E(c["title"])}: {c["status"]}">{E(c["id"])}</button>')
        groups.append(f'<div class="grp"><h4>{E(obj["objective"])} {E(obj["title"])}</h4>'
                      f'<div class="tiles">{"".join(tiles)}</div></div>')

    clauses = "".join(
        f'<div class="cl"><div class="cl-h"><span>Clause {c["id"]} {E(c["title"])}</span>'
        f'<b>{c["score"]}%</b></div><div class="bar"><i class="{"ok" if c["score"] >= 90 else "mid" if c["score"] >= 70 else "low"}" '
        f'style="width:{c["score"]}%"></i></div><p class="sub">{c["pdca"]}'
        + (" | missing: " + ", ".join(E(r["id"]) for r in c["requirements"] if r["status"] != "implemented")
           if any(r["status"] != "implemented" for r in c["requirements"]) else "") + "</p></div>"
        for c in conf["clauses"])

    run_rows = []
    for r in runs:
        stages = json.loads(r["stages"] or "[]")
        chips = "".join(f'<span class="chip c-{st["status"]}">{E(st["stage"])}</span>' for st in stages)
        gate = json.loads(r["gate"]) if r["gate"] else None
        deny = gate["decision"]["deny"] if gate else next((st.get("deny", []) for st in stages if st["stage"] == "gate"), [])
        if not gate and r["status"] == "blocked_at_data":
            deny = ["Stopped before training: data failed provenance or poisoning checks"]
        test = next((st for st in stages if st["stage"] == "test"), None)
        metrics = (f'accuracy {test["clean_accuracy"]:.1%}, fraud caught {test["clean_fraud_recall"]:.1%}, '
                   f'caught under attack {test["robust_fraud_recall"]:.1%}, false alarms {test["false_positive_rate"]:.1%}'
                   if test else "")
        run_rows.append(f'<tr><td><b>{E(r["label"] or r["id"])}</b><br><span class="sub">{E(r["id"])}</span></td>'
                        f'<td>{chips}</td><td><span class="pill p-{E(r["status"])}">{E(r["status"].replace("_", " "))}</span>'
                        f'<p class="sub">{E(metrics)}</p>'
                        + ("<ul class='deny'>" + "".join(f"<li>{E(d)}</li>" for d in deny) + "</ul>"
                           if deny and r["status"] != "deployed" else "") + "</td></tr>")

    inc_html = []
    for i in incidents:
        tl = json.loads(i["timeline"])
        steps = "".join(f'<li><b>{E(x["state"].replace("_", " "))}</b> {E(x["note"])}</li>' for x in tl)
        inc_html.append(f'<article class="inc sev-{E(i["severity"])}"><header><span class="pill p-sev-{E(i["severity"])}">'
                        f'{E(i["severity"])}</span> <b>{E(i["id"])}</b> {E(i["title"])}</header>'
                        f'<ol>{steps}</ol></article>')

    risk_rows = "".join(
        f'<tr><td>{E(r["name"])}<p class="sub">{E(r["rationale"] or "")}</p></td><td>{E(r["system_id"])}</td>'
        f'<td class="num">{r["likelihood"]} x {r["impact"]} = <b>{r["score"]}</b></td>'
        f'<td><span class="pill p-lv-{E(r["level"])}">{E(r["level"])}</span></td>'
        f'<td class="num">{r["residual_score"] if r["residual_score"] is not None else "-"}</td>'
        f'<td>{E(r["status"])}</td><td>{E(r["controls"] or "")}</td><td>{E(r["owasp"] or "")}</td></tr>'
        for r in risks)

    ev_rows = "".join(f'<tr><td>{E(sys_)}</td><td>{E(typ)}</td><td class="num">{n}</td></tr>'
                      for (sys_, typ), n in sorted(ev_counts.items(), key=lambda kv: -kv[1]))
    ledger_rows = "".join(
        f'<tr><td class="num">{e["seq"]}</td><td>{E(e["type"])}</td><td>{E(e["summary"])}</td>'
        f'<td><code>{e["entry_hash"][:12]}</code></td></tr>' for e in ledger_tail)
    notif = ", ".join(f'{E(cfg.raci["roles"].get(n["role"], n["role"]))} ({n["n"]})' for n in notifications)
    chart = _chart(_robustness_series(store), t["gate_epsilon"], t["max_evasion_success_rate"])
    open_inc = sum(1 for i in incidents if i["state"] != "closed")

    page = TEMPLATE.format(
        org=E(cfg.platform["organization"]["name"]), generated=E(now()), impl=s["implemented"], total=s["total"],
        partial=s["partial"], gap=s["gap"], groups="".join(groups), clauses=clauses,
        chain_cls="ok" if chain["intact"] else "bad",
        chain_txt=f'Evidence chain intact, {chain["entries"]} entries' if chain["intact"]
        else f'Evidence chain broken: {len(chain["problems"])} problems',
        runs="".join(run_rows), chart=chart, incidents="".join(inc_html) or "<p>No incidents.</p>",
        n_inc=len(incidents), open_inc=open_inc, risks=risk_rows, events=ev_rows, n_events=len(events),
        ledger=ledger_rows, notif=notif or "none", eps=t["gate_epsilon"],
        maxev=int(t["max_evasion_success_rate"] * 100))
    path = home() / "reports" / "dashboard.html"
    path.write_text(page, encoding="utf-8")
    return str(path)


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Amanah AI assurance dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Source+Sans+3:wght@400;600;700&family=Source+Serif+4:opsz,wght@8..60,600;8..60,700&display=swap" rel="stylesheet">
<style>
:root{{--bg:#eef1f5;--panel:#ffffff;--ink:#17233b;--text:#2f3b52;--muted:#5f6b80;--line:#d7dde6;
--ok:#0d7f73;--ok-bg:#d9f0ec;--mid:#a86b12;--mid-bg:#f8ead2;--bad:#b4381f;--bad-bg:#f8dcd4;--accent:#1f4f8f;
box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{--bg:#0f1624;--panel:#18223a;--ink:#eef2f8;--text:#d3dae6;
--muted:#9aa6ba;--line:#2b3854;--ok:#3cc4b2;--ok-bg:#123a37;--mid:#e0a64a;--mid-bg:#3b2e17;--bad:#f07a5f;--bad-bg:#43211b;--accent:#7fb0ff}}}}
:root[data-theme="dark"]{{--bg:#0f1624;--panel:#18223a;--ink:#eef2f8;--text:#d3dae6;--muted:#9aa6ba;--line:#2b3854;
--ok:#3cc4b2;--ok-bg:#123a37;--mid:#e0a64a;--mid-bg:#3b2e17;--bad:#f07a5f;--bad-bg:#43211b;--accent:#7fb0ff}}
html{{scroll-padding-top:env(safe-area-inset-top,0px)}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 "Source Sans 3",system-ui,-apple-system,"Segoe UI",sans-serif;font-variant-numeric:tabular-nums}}
h1,h2,h3{{font-family:"Source Serif 4",Georgia,serif;color:var(--ink);margin:0}}
h1{{font-size:clamp(26px,4vw,38px);line-height:1.15}}h2{{font-size:24px;margin-bottom:4px}}
h4{{margin:0 0 6px;font-size:13px;color:var(--muted);font-weight:600}}
.wrap{{max-width:1240px;margin:0 auto;padding:28px 20px 60px}}
header.top{{display:flex;flex-wrap:wrap;justify-content:space-between;gap:16px;align-items:flex-end;margin-bottom:24px}}
.meta{{color:var(--muted);font-size:14px}}
.badge{{display:inline-block;padding:6px 12px;border-radius:999px;font-weight:600;font-size:14px}}
.badge.ok{{background:var(--ok-bg);color:var(--ok)}}.badge.bad{{background:var(--bad-bg);color:var(--bad)}}
section{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:22px;margin-bottom:20px}}
.intro{{color:var(--muted);margin:0 0 16px;max-width:75ch}}
.hero{{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(0,1fr);gap:28px}}
@media (max-width:900px){{.hero{{grid-template-columns:1fr}}}}
.big{{font-family:"Source Serif 4",Georgia,serif;font-size:56px;line-height:1;color:var(--ink)}}
.big small{{font-size:22px;color:var(--muted)}}
.legend{{display:flex;flex-wrap:wrap;gap:14px;font-size:14px;margin:10px 0 18px}}
.legend span::before{{content:"";display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:6px;vertical-align:-1px}}
.legend .l-i::before{{background:var(--ok)}}.legend .l-p::before{{background:var(--mid)}}.legend .l-g::before{{background:var(--bad)}}
.grps{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:14px}}
.tiles{{display:flex;flex-wrap:wrap;gap:6px}}
.tile{{font:600 13px/1 "Source Sans 3",system-ui,sans-serif;border:0;border-radius:6px;padding:9px 8px;min-width:58px;cursor:pointer;color:#fff}}
.tile:focus-visible{{outline:3px solid var(--accent);outline-offset:2px}}
.st-implemented{{background:var(--ok)}}.st-partial{{background:var(--mid)}}.st-gap{{background:var(--bad)}}
#detail{{margin-top:16px;padding:14px;border-left:4px solid var(--accent);background:var(--bg);border-radius:6px;min-height:64px}}
.cl{{margin-bottom:12px}}.cl-h{{display:flex;justify-content:space-between;gap:10px;font-size:15px}}
.bar{{height:10px;background:var(--bg);border-radius:6px;overflow:hidden;margin:4px 0 2px}}
.bar i{{display:block;height:100%}}.bar .ok{{background:var(--ok)}}.bar .mid{{background:var(--mid)}}.bar .low{{background:var(--bad)}}
.sub{{color:var(--muted);font-size:13px;margin:2px 0 0}}
.scroll{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;font-size:14px}}
th{{text-align:left;color:var(--muted);font-weight:600;border-bottom:1px solid var(--line);padding:8px}}
td{{border-bottom:1px solid var(--line);padding:10px 8px;vertical-align:top}}.num{{white-space:nowrap}}
.chip{{display:inline-block;font-size:12px;padding:3px 8px;border-radius:5px;margin:2px;background:var(--bg)}}
.c-pass{{background:var(--ok-bg);color:var(--ok)}}.c-fail{{background:var(--bad-bg);color:var(--bad)}}.c-held{{background:var(--mid-bg);color:var(--mid)}}
.pill{{display:inline-block;font-size:13px;font-weight:600;padding:2px 10px;border-radius:999px;background:var(--bg)}}
.p-deployed,.p-lv-low,.p-lv-medium{{background:var(--ok-bg);color:var(--ok)}}
.p-awaiting_approval,.p-lv-high,.p-sev-high,.p-sev-medium{{background:var(--mid-bg);color:var(--mid)}}
.p-rejected,.p-blocked_at_data,.p-lv-critical,.p-sev-critical{{background:var(--bad-bg);color:var(--bad)}}
.deny{{margin:6px 0 0;padding-left:18px;font-size:13px;color:var(--bad)}}
.two{{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,1fr);gap:24px}}@media (max-width:900px){{.two{{grid-template-columns:1fr}}}}
svg{{width:100%;height:auto}}svg .grid{{stroke:var(--line)}}svg .ax{{fill:var(--muted);font-size:12px}}
svg .gate{{stroke:var(--accent);stroke-dasharray:4 4}}svg .limit{{stroke:var(--bad);stroke-dasharray:2 4}}
svg polyline{{fill:none;stroke-width:3}}svg polyline.s-fail{{stroke:var(--bad)}}svg polyline.s-pass{{stroke:var(--ok)}}
svg circle.s-fail{{fill:var(--bad)}}svg circle.s-pass{{fill:var(--ok)}}svg text.lbl{{font-size:13px;font-weight:600}}
svg text.s-fail{{fill:var(--bad)}}svg text.s-pass{{fill:var(--ok)}}
.inc{{border:1px solid var(--line);border-radius:8px;padding:14px;margin-bottom:12px}}
.inc ol{{margin:10px 0 0;padding-left:20px;font-size:14px}}.inc li{{margin-bottom:4px}}
code{{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:12px}}
nav{{display:flex;flex-wrap:wrap;gap:14px;font-size:14px;margin-bottom:18px}}nav a{{color:var(--accent)}}
</style></head><body><div class="wrap">
<header class="top"><div><h1>Amanah AI assurance dashboard</h1>
<p class="meta">{org}. ISO/IEC 42001:2023 AI management system. Generated {generated}.</p></div>
<span class="badge {chain_cls}">{chain_txt}</span></header>
<nav><a href="#controls">Controls</a><a href="#releases">Model releases</a><a href="#robustness">Robustness</a>
<a href="#incidents">Incidents</a><a href="#risks">Risk register</a><a href="#telemetry">Telemetry</a><a href="#ledger">Evidence ledger</a></nav>

<section id="controls" class="hero"><div>
<h2>Annex A controls</h2><p class="intro">Each square is one of the 38 reference controls. A control is green only when the evidence ledger holds every kind of proof it needs. Select a square to see what it needs and what is missing.</p>
<div class="big">{impl}<small> of {total} implemented</small></div>
<div class="legend"><span class="l-i">Implemented</span><span class="l-p">Partial ({partial})</span><span class="l-g">Gap ({gap})</span></div>
<div class="grps">{groups}</div>
<div id="detail" aria-live="polite">Select a control to see its evidence.</div>
</div><div><h2>Clauses 4 to 10</h2><p class="intro">The mandatory management-system requirements, scored from evidence and grouped by Plan, Do, Check, Act.</p>{clauses}</div></section>

<section id="releases"><h2>Model releases through the secure pipeline</h2>
<p class="intro">Every retrain passes data checks, training, signing, testing and the policy gate in order. Nothing reaches production unless the Open Policy Agent gate allows it.</p>
<div class="scroll"><table><thead><tr><th>Change</th><th>Stages</th><th>Outcome and reasons</th></tr></thead><tbody>{runs}</tbody></table></div></section>

<section id="robustness" class="two"><div><h2>Adversarial robustness</h2>
<p class="intro">Share of caught fraud an attacker can flip to "legitimate" with IBM ART's PGD attack, by attack strength. The dashed vertical line is the gate's test strength ({eps}); the dotted line is the {maxev}% limit.</p>{chart}</div>
<div id="incidents"><h2>Incidents</h2><p class="intro">{n_inc} incidents recorded, {open_inc} open. Each one moves through contain, notify, root cause, report and close, and every step is written to the evidence ledger.</p>{incidents}</div></section>

<section id="risks"><h2>Risk register</h2><p class="intro">Score is likelihood times impact. The note under each risk shows which system attributes added points. Gaps found on this dashboard are fed back in as risks at the bottom.</p>
<div class="scroll"><table><thead><tr><th>Risk</th><th>System</th><th>Score</th><th>Level</th><th>Residual</th><th>Status</th><th>Controls</th><th>OWASP</th></tr></thead><tbody>{risks}</tbody></table></div></section>

<section id="telemetry" class="two"><div><h2>Security telemetry</h2><p class="intro">{n_events} events in the unified log that the correlation engine reads.</p>
<div class="scroll"><table><thead><tr><th>System</th><th>Event</th><th>Count</th></tr></thead><tbody>{events}</tbody></table></div></div>
<div id="ledger"><h2>Evidence ledger</h2><p class="intro">Latest entries. Each hash covers the entry before it, so changing any past record breaks the chain. Notifications routed by RACI: {notif}.</p>
<div class="scroll"><table><thead><tr><th>#</th><th>Type</th><th>Summary</th><th>Hash</th></tr></thead><tbody>{ledger}</tbody></table></div></div></section>
</div>
<script>
document.querySelectorAll('.tile').forEach(function(b){{b.addEventListener('click',function(){{
var c=JSON.parse(b.dataset.c),d=document.getElementById('detail');
d.innerHTML='<b>'+c.id+' '+c.title+'</b> is '+c.status+'. Needs: '+c.evidence.join(', ')+'. Evidence entries held: '+c.count+
(c.missing.length?'. <span style="color:var(--bad)">Missing: '+c.missing.join(', ')+'</span>':'.');}});}});
</script></body></html>
"""
