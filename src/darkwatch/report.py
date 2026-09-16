"""Turn hits into a report a human can act on: Markdown, HTML and JSON, plus per-hit actions.

Every run writes a timestamped set and refreshes `latest.*`; the desktop notification opens
`latest.html`. Old timestamped sets beyond `keep_reports` are deleted.
"""

from __future__ import annotations

import html
import json
import re
import shutil
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from .matcher import SEVERITIES, severity_rank
from .sources import DOC_SOURCES
from .storage import Hit

# What to do, keyed by the kind of identifier that was found.
ACTIONS_BY_TYPE: dict[str, list[str]] = {
    "email": [
        "Change the password of this mailbox and of every account that used the same password.",
        "Turn on MFA (authenticator app or passkey, not SMS) for the mailbox and the accounts behind it.",
        "Expect targeted phishing that quotes real details; do not trust mail that references this exposure.",
    ],
    "phone": [
        "Ask the carrier for a SIM-swap / port-out lock and set a SIM PIN.",
        "Treat unexpected OTP messages as an attack in progress, not noise.",
        "If the number appears next to address or ID data, consider changing it.",
    ],
    "domain": [
        "Alert the security / IT owner of the domain.",
        "Check the source for employee addresses at this domain and force password resets for those found.",
        "Watch for lookalike domains and impersonation of this domain.",
    ],
    "username": [
        "Change the password wherever this handle is used; assume password reuse.",
        "Review recent logins on those services for unfamiliar sessions or devices.",
    ],
    "name": [
        "Confirm it is the same person or organisation before acting; a name alone is weak evidence.",
        "Look for co-occurring details (address, phone, ID numbers) in the same page.",
    ],
    "keyword": ["Review manually; keywords are literal matches with no built-in meaning."],
}

PRESERVE = "Preserve evidence before the page changes: URL, UTC time, a screenshot taken in Tor Browser."

# What to do, keyed by the kind of evidence.
ACTIONS_BY_SOURCE: dict[str, list[str]] = {
    "leaksite": [
        "Treat this as a live incident: a ransomware group claims to hold this organisation's data.",
        "Engage incident response; do not contact or pay the group without legal advice.",
        (
            "In India, report to CERT-In (incident@cert-in.org.in) within 6 hours of noticing, as its "
            "April 2022 directions require; elsewhere, report to the national CERT and regulator."
        ),
    ],
    "breach": [
        "Change the password at the breached service and anywhere it was reused.",
    ],
    "paste": [
        "A paste means the data was shared publicly; change the associated passwords now.",
    ],
    "onion": [PRESERVE],
    "ahmia-index": [
        "Open the page in Tor Browser to confirm the listing still contains the identifier.",
    ],
    "site": [
        "A public profile under this handle. Confirm it is really this person.",
        "Review what it exposes (real name, employer, location, other handles) and tighten it if unwanted.",
        "Reuse of the same handle links these accounts together; consider distinct handles for sensitive ones.",
    ],
}

# Extra actions when the evidence carries a signal.
ACTIONS_BY_SIGNAL: dict[str, list[str]] = {
    "credentials": ["Assume the password is compromised; change it now and check for reuse."],
    "financial": ["Contact the bank or card issuer; block or reissue the card; watch statements."],
    "government_id": [
        "Report the exposed ID to the issuing authority and enable fraud alerts or credit monitoring."
    ],
    "sale": [
        "Possible listing for sale: treat the data as being in criminal hands.",
        PRESERVE,
        "Report it: in India at cybercrime.gov.in or helpline 1930; elsewhere to the national CERT.",
    ],
    "dox": [
        "Doxxing indicators. Tell the person and review physical-safety measures.",
        PRESERVE,
        "Report to the platform, if any, and to law enforcement.",
    ],
    "access": [
        "Claimed network access or ransomware. Isolate affected systems, rotate service credentials, review logs.",
        "Escalate to the organisation's incident response owner immediately.",
    ],
}


def actions_for(hit: Hit) -> list[str]:
    out: list[str] = []
    for group in (
        ACTIONS_BY_SOURCE.get(hit.source, []),
        ACTIONS_BY_TYPE.get(hit.term_type, []),
        *(ACTIONS_BY_SIGNAL.get(sig, []) for sig in hit.signals),
    ):
        for a in group:
            if a not in out:
                out.append(a)
    return out


def group_by_target(hits: list[Hit]) -> dict[str, list[Hit]]:
    g: dict[str, list[Hit]] = defaultdict(list)
    for h in hits:
        g[h.target].append(h)
    for t_hits in g.values():
        t_hits.sort(key=lambda h: (-severity_rank(h.severity), -h.score, h.first_seen, h.id))
    return dict(sorted(g.items()))


def severity_counts(hits: list[Hit]) -> dict[str, int]:
    c = dict.fromkeys(SEVERITIES, 0)
    for h in hits:
        c[h.severity] = c.get(h.severity, 0) + 1
    return c


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _source_rows(run_info: dict) -> list[dict]:
    return [{"name": name, **st} for name, st in (run_info.get("source_stats") or {}).items()]


def _tor_line(run_info: dict) -> str:
    tor = run_info.get("tor") or {}
    if not tor.get("used"):
        reason = tor.get("error") or "not needed by the selected sources"
        return f"not used ({reason})"
    parts = ["verified Tor exit" if tor.get("is_tor") else f"NOT verified ({tor.get('check_error') or 'not a Tor exit'})"]
    if tor.get("managed"):
        parts.append(f"started by darkwatch, ready in {tor.get('bootstrap_seconds')}s")
    else:
        parts.append("existing Tor on the proxy port")
    return "; ".join(parts)


MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+!|<>~])")


def md(text: str) -> str:
    """Untrusted text made inert for Markdown: one line, every markup character escaped, so a
    hostile page title cannot become an image (a clearnet fetch from the owner's IP), a link,
    a heading or a fake list of actions."""
    return MD_SPECIAL.sub(r"\\\1", " ".join(str(text).split()))


def _hidden_line(run_info: dict | None) -> str:
    n = (run_info or {}).get("hidden_hits", 0)
    if not n:
        return ""
    return (f"{n} open hit(s) belong to targets that are no longer in the watchlist and are not shown "
            "(`darkwatch hits` lists them).")


def to_markdown(hits: list[Hit], *, title: str, run_info: dict | None = None) -> str:
    lines = [f"# {title}", "", f"Generated {_stamp()}.", ""]
    if run_info:
        lines += [
            "| Run | Duration | Documents checked | New hits | Escalated | Already known | Errors |",
            "|---|---|---|---|---|---|---|",
            (
                f"| {run_info.get('run_id', '-')} | {run_info.get('seconds', '-')} s | {run_info.get('pages', 0)} | "
                f"{run_info.get('new_hits', 0)} | {run_info.get('escalated_hits', 0)} | "
                f"{run_info.get('seen_hits', 0)} | {len(run_info.get('errors', []))} |"
            ),
            "",
            f"Tor: {_tor_line(run_info)}.",
            "",
        ]
        rows = _source_rows(run_info)
        if rows:
            lines += [
                "| Source | Documents | Hits | New | Onion pages | Seconds | Notes |",
                "|---|---|---|---|---|---|---|",
            ]
            for r in rows:
                onion = f"{r.get('onion_ok', 0)}/{r.get('onion_fetches', 0)}" if r.get("onion_fetches") else "-"
                lines.append(
                    f"| {r['name']} | {r.get('documents', 0)} | {r.get('hits', 0)} | {r.get('new_hits', 0)} | "
                    f"{onion} | {r.get('seconds', 0)} | {r.get('note', '')} |"
                )
            lines.append("")
    counts = severity_counts(hits)
    lines += ["## Open hits", "", "| Severity | Hits |", "|---|---|"]
    lines += [f"| {sev} | {counts.get(sev, 0)} |" for sev in reversed(SEVERITIES)]
    lines.append("")
    if not hits:
        lines += ["No open hits.", ""]
    if _hidden_line(run_info):
        lines += [_hidden_line(run_info), ""]
    for target, t_hits in group_by_target(hits).items():
        lines += [f"## {md(target)}", ""]
        for h in t_hits:
            lines += [
                f"### [{h.severity}] {md(h.term)} ({h.term_type}) in {h.source} evidence, hit #{h.id}",
                "",
                f"- **Where:** {md(h.url)}",
            ]
            if h.title:
                lines.append(f"- **Title:** {md(h.title)}")
            lines += [
                f"- **First seen:** {h.first_seen}. **Last seen:** {h.last_seen}.",
                f"- **Signals:** {', '.join(h.signals) or 'none'}. **Score:** {h.score}.",
                f"- **Status:** {h.status}" + (f" ({md(h.note)})" if h.note else ""),
                "",
                "> " + md(h.snippet),
                "",
                "**Recommended actions**",
                "",
            ]
            lines += [f"1. {a}" for a in actions_for(h)]
            lines.append("")
    if run_info and run_info.get("errors"):
        lines += ["## Errors during the run", ""]
        lines += [f"- {md(e)}" for e in run_info["errors"]]
        lines.append("")
    lines += [
        "---",
        (
            "Evidence handling: Darkwatch stores only the URL, times and a short snippet. Take your own "
            "timestamped screenshot in Tor Browser before a page changes. Do not download files from the source. "
            "Triage with `darkwatch ack`, `resolve` or `false-positive`. "
            "Score = identifier weight + one per signal + evidence weight; "
            "the signal `dated` means the evidence is at least 3 years old and costs one point."
        ),
    ]
    return "\n".join(lines) + "\n"


_CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1c1c1c;--muted:#5d5d5d;--line:#dedede;--code:#efefec;
--crit:#b3261e;--high:#c25400;--med:#9a7400;--low:#2e7d32}
@media (prefers-color-scheme:dark){:root{--bg:#161616;--card:#202020;--ink:#ececec;--muted:#a3a3a3;
--line:#343434;--code:#2b2b2b;--crit:#ff6b60;--high:#ff9a45;--med:#e0bd3f;--low:#6fcf73}}
*{box-sizing:border-box}
body{font:15px/1.5 system-ui,"Segoe UI",sans-serif;background:var(--bg);color:var(--ink);margin:0}
main{max-width:980px;margin:0 auto;padding:1.5rem 1rem 4rem}
h1{font-size:1.5rem;margin:.2rem 0}h2{font-size:1.15rem;margin:2rem 0 .6rem}
small,.muted{color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.6rem;margin:1rem 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.6rem .8rem}
.tile b{display:block;font-size:1.5rem}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;background:var(--card)}
td,th{border:1px solid var(--line);padding:.35rem .55rem;text-align:left;vertical-align:top;font-size:.9rem}
.filters{display:flex;flex-wrap:wrap;gap:.4rem;margin:1rem 0}
.filters button{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--ink);
border-radius:999px;padding:.2rem .8rem;cursor:pointer}
.filters button[aria-pressed=true]{border-color:var(--ink);font-weight:600}
.hit{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--muted);
border-radius:6px;padding:.7rem 1rem;margin:.7rem 0}
.hit.CRITICAL{border-left-color:var(--crit)}.hit.HIGH{border-left-color:var(--high)}
.hit.MEDIUM{border-left-color:var(--med)}.hit.LOW{border-left-color:var(--low)}
.sev{font-weight:700;font-size:.8rem;letter-spacing:.03em}
.sev.CRITICAL{color:var(--crit)}.sev.HIGH{color:var(--high)}.sev.MEDIUM{color:var(--med)}.sev.LOW{color:var(--low)}
.hit h3{font-size:1rem;margin:.1rem 0 .3rem;overflow-wrap:anywhere}
.meta{font-size:.88rem;overflow-wrap:anywhere}
blockquote{background:var(--code);margin:.5rem 0;padding:.5rem .7rem;border-radius:4px;
font:.82rem/1.45 ui-monospace,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
code{background:var(--code);padding:0 .25rem;border-radius:3px}
details summary{cursor:pointer;font-weight:600;font-size:.9rem}
ol{margin:.3rem 0 .2rem;padding-left:1.3rem}
"""

_JS = """
const buttons=[...document.querySelectorAll('.filters button')];
function apply(){const on=buttons.filter(b=>b.getAttribute('aria-pressed')==='true').map(b=>b.dataset.sev);
document.querySelectorAll('.hit').forEach(h=>{h.hidden=on.length>0&&!on.includes(h.dataset.sev)});}
buttons.forEach(b=>b.addEventListener('click',()=>{b.setAttribute('aria-pressed',
b.getAttribute('aria-pressed')==='true'?'false':'true');apply();}));
"""


def to_html(hits: list[Hit], *, title: str, run_info: dict | None = None) -> str:
    e = html.escape
    counts = severity_counts(hits)
    p = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        f"<title>{e(title)}</title><style>{_CSS}</style></head><body><main>",
        f"<h1>{e(title)}</h1><small>Generated {_stamp()}</small>",
        "<div class=\"tiles\">",
    ]
    p += [f"<div class=\"tile\"><span class=\"sev {s}\">{s}</span><b>{counts.get(s, 0)}</b></div>"
          for s in reversed(SEVERITIES)]
    if run_info:
        p.append(f"<div class=\"tile\"><span class=\"muted\">New this run</span><b>{run_info.get('new_hits', 0)}</b></div>")
    p.append("</div>")
    if run_info:
        p.append(
            f"<p class=\"meta\">Run {run_info.get('run_id', '-')}: {run_info.get('pages', 0)} documents checked in "
            f"{run_info.get('seconds', '-')} s, {run_info.get('escalated_hits', 0)} escalated, "
            f"{run_info.get('seen_hits', 0)} matches already known, "
            f"{len(run_info.get('errors', []))} errors. Tor: {e(_tor_line(run_info))}.</p>"
        )
        rows = _source_rows(run_info)
        if rows:
            p.append("<div class=\"scroll\"><table><tr><th>Source</th><th>Documents</th><th>Hits</th><th>New</th>"
                     "<th>Onion pages</th><th>Seconds</th><th>Notes</th></tr>")
            for r in rows:
                onion = f"{r.get('onion_ok', 0)}/{r.get('onion_fetches', 0)}" if r.get("onion_fetches") else "-"
                p.append(
                    f"<tr><td>{e(r['name'])}</td><td>{r.get('documents', 0)}</td><td>{r.get('hits', 0)}</td>"
                    f"<td>{r.get('new_hits', 0)}</td><td>{onion}</td><td>{r.get('seconds', 0)}</td>"
                    f"<td>{e(str(r.get('note', '')))}</td></tr>"
                )
            p.append("</table></div>")
    p.append("<h2>Open hits</h2>")
    if hits:
        p.append("<div class=\"filters\" aria-label=\"Filter by severity\">"
                 + "".join(f"<button type=\"button\" data-sev=\"{s}\" aria-pressed=\"false\">{s}</button>"
                           for s in reversed(SEVERITIES) if counts.get(s))
                 + "</div>")
    else:
        p.append("<p>No open hits.</p>")
    if _hidden_line(run_info):
        p.append(f"<p class=\"meta muted\">{e(_hidden_line(run_info))}</p>")
    for target, t_hits in group_by_target(hits).items():
        p.append(f"<h2>{e(target)} <small>({len(t_hits)})</small></h2>")
        for h in t_hits:
            source_desc = DOC_SOURCES.get(h.source, h.source)
            p.append(f"<article class=\"hit {h.severity}\" data-sev=\"{h.severity}\">")
            p.append(f"<span class=\"sev {h.severity}\">{h.severity}</span> <small>#{h.id} · score {h.score} · "
                     f"{e(h.status)}</small>")
            p.append(f"<h3>{e(h.title or h.url)}</h3>")
            p.append(f"<div class=\"meta\"><code>{e(h.term)}</code> ({e(h.term_type)}) found in "
                     f"<span title=\"{e(source_desc)}\">{e(h.source)}</span> evidence. "
                     f"Signals: {e(', '.join(h.signals) or 'none')}.</div>")
            p.append(f"<div class=\"meta muted\">{e(h.url)}<br>first seen {e(h.first_seen)} · last seen {e(h.last_seen)}"
                     + (f" · note: {e(h.note)}" if h.note else "") + "</div>")
            p.append(f"<blockquote>{e(h.snippet)}</blockquote>")
            p.append("<details open><summary>Recommended actions</summary><ol>"
                     + "".join(f"<li>{e(a)}</li>" for a in actions_for(h)) + "</ol></details>")
            p.append("</article>")
    if run_info and run_info.get("errors"):
        p.append("<h2>Errors during the run</h2><ul>" + "".join(f"<li>{e(x)}</li>" for x in run_info["errors"]) + "</ul>")
    p.append(
        "<hr><small>Evidence handling: Darkwatch stores only the URL, times and a short snippet. Take your own "
        "timestamped screenshot in Tor Browser before a page changes. Do not download files from the source. "
        "Triage with <code>darkwatch ack</code>, <code>resolve</code> or <code>false-positive</code>. "
        "Score = identifier weight + one per signal + evidence weight; the signal <code>dated</code> means "
        "the evidence is at least 3 years old and costs one point.</small>"
    )
    p.append(f"</main><script>{_JS}</script></body></html>")
    return "\n".join(p)


def to_json(hits: list[Hit], *, run_info: dict | None = None) -> str:
    return json.dumps(
        {
            "generated": _stamp(),
            "run": run_info or {},
            "summary": severity_counts(hits),
            "hits": [
                {
                    "id": h.id, "target": h.target, "term": h.term, "term_type": h.term_type,
                    "source": h.source, "url": h.url, "title": h.title, "snippet": h.snippet,
                    "signals": h.signals, "score": h.score, "severity": h.severity,
                    "first_seen": h.first_seen, "last_seen": h.last_seen, "status": h.status,
                    "note": h.note, "actions": actions_for(h),
                }
                for h in hits
            ],
        },
        indent=2,
        ensure_ascii=False,
    )


RENDERERS = {"md": to_markdown, "html": to_html}
STAMP_RE = re.compile(r"^darkwatch-(\d{8}-\d{6})\.(md|html|json)$")


def prune_reports(out: Path, keep: int) -> int:
    stamps = sorted({m.group(1) for f in out.iterdir() if (m := STAMP_RE.match(f.name))}, reverse=True)
    removed = 0
    for stamp in stamps[keep:]:
        for f in out.glob(f"darkwatch-{stamp}.*"):
            f.unlink()
            removed += 1
    return removed


def write_reports(
    hits: list[Hit],
    out_dir: str | Path,
    *,
    title: str,
    run_info: dict | None = None,
    formats: tuple[str, ...] = ("md", "html", "json"),
    keep: int = 60,
) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    written = []
    for fmt in formats:
        p = out / f"darkwatch-{stamp}.{fmt}"
        if fmt == "json":
            body = to_json(hits, run_info=run_info)
        elif fmt in RENDERERS:
            body = RENDERERS[fmt](hits, title=title, run_info=run_info)
        else:
            raise ValueError(f"unknown format {fmt}")
        p.write_text(body, encoding="utf-8")
        shutil.copyfile(p, out / f"latest.{fmt}")
        written.append(p)
    if keep > 0:
        prune_reports(out, keep)
    return written
