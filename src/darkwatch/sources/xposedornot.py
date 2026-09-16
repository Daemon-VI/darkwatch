"""XposedOrNot — free, keyless breach and paste exposure for email addresses.

`GET https://api.xposedornot.com/v1/breach-analytics?email=<email>` returns every indexed breach
that included the address, with the data classes each one exposed, plus a paste summary. That
fills the gap psbdmp left (its API is gone) and makes breach checks work without a paid HIBP key.

Free-tier limits per IP, from the API docs (checked 2026-09-16): 2 requests/second, 25/hour,
100/day. The source spaces calls and stops at `MAX_EMAILS_PER_RUN`.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from urllib.parse import quote

from ..config import Settings, Term
from . import Document, SourceContext

log = logging.getLogger(__name__)

ANALYTICS = "https://api.xposedornot.com/v1/breach-analytics?email={email}"
MAX_EMAILS_PER_RUN = 20


def breach_document(email: str, b: dict) -> Document:
    name = str(b.get("breach") or "unknown")
    classes = str(b.get("xposed_data") or "").replace(";", ", ")
    records = b.get("xposed_records")
    text = (
        f"{email} is in the {name} breach"
        f" ({b.get('domain') or 'no domain'}, {b.get('xposed_date') or 'date unknown'}"
        + (f", {records:,} records" if isinstance(records, int) else "")
        + f"). Exposed: {classes or 'not stated'}."
        + (f" Password storage risk: {b['password_risk']}." if b.get("password_risk") else "")
        + (f" {b['details']}" if b.get("details") else "")
    )
    return Document(
        url=f"https://xposedornot.com/xposed#{quote(name)}",
        title=f"Breach: {name}",
        text=text,
        source="breach",
        meta={"provider": "XposedOrNot", "breach": name, "date": b.get("xposed_date"), "classes": classes},
        signal_text=classes,
        evidence_date=str(b.get("xposed_date") or ""),
    )


def paste_documents(email: str, data: dict) -> list[Document]:
    docs: list[Document] = []
    exposed = data.get("ExposedPastes")
    items: list = []
    if isinstance(exposed, list):
        items = exposed
    elif isinstance(exposed, dict):
        items = exposed.get("pastes_details") or exposed.get("pastes") or []
    for p in items:
        if not isinstance(p, dict):
            continue
        pid = p.get("id") or p.get("paste_id") or p.get("title") or "paste"
        src = p.get("source") or p.get("site") or "a paste site"
        docs.append(
            Document(
                url=f"https://xposedornot.com/xposed#paste-{quote(str(pid))}",
                title=f"Paste on {src}",
                text=(
                    f"{email} appeared in a public paste on {src}"
                    f" ({p.get('xposed_date') or p.get('date') or 'date unknown'})."
                ),
                source="paste",
                meta={"provider": "XposedOrNot", "paste": pid},
                signal_text="",
            )
        )
    summary = data.get("PastesSummary") or {}
    try:
        count = int(summary.get("cnt") or 0)
    except (TypeError, ValueError):
        count = 0
    if count and not docs:
        docs.append(
            Document(
                url=f"https://xposedornot.com/xposed#pastes-{quote(email)}",
                title=f"{count} paste exposure(s)",
                text=(
                    f"{email} appeared in {count} public paste(s)"
                    f" on {summary.get('domain') or 'paste sites'}, most recently {summary.get('tmpstmp') or 'unknown'}."
                ),
                source="paste",
                meta={"provider": "XposedOrNot", "count": count},
                signal_text="",
            )
        )
    return docs


def parse_analytics(email: str, data: dict) -> list[Document]:
    docs: list[Document] = []
    exposed = data.get("ExposedBreaches") or {}
    for b in exposed.get("breaches_details") or []:
        if isinstance(b, dict):
            docs.append(breach_document(email, b))
    docs.extend(paste_documents(email, data))
    return docs


class XposedOrNotSource:
    name = "xposedornot"
    description = "breach and paste exposure for each email (XposedOrNot, free, no key)"

    def unavailable_reason(self, settings: Settings) -> str:
        return ""

    def discover(self, terms: list[Term], ctx: SourceContext) -> Iterator[Document]:
        s = ctx.settings
        emails = sorted({t.value for t in terms if t.type == "email"})
        if len(emails) > MAX_EMAILS_PER_RUN:
            ctx.error(
                f"xposedornot: {len(emails)} emails but the free tier allows ~25 lookups/hour; "
                f"checking the first {MAX_EMAILS_PER_RUN}"
            )
            emails = emails[:MAX_EMAILS_PER_RUN]
        for email in emails:
            ctx.throttle("xposedornot", 1.5)
            ctx.progress(f"xposedornot: {email}")
            try:
                r = ctx.clear.get(ANALYTICS.format(email=quote(email)), timeout=s.timeout)
            except Exception as exc:  # noqa: BLE001
                ctx.error(f"xposedornot lookup failed for {email}: {exc}")
                continue
            if r.status_code == 429:
                ctx.error("xposedornot: rate limited (429); free tier is 25/hour, 100/day per IP")
                return
            if r.status_code == 404:
                continue
            if not r.ok:
                ctx.error(f"xposedornot {email}: HTTP {r.status_code}")
                continue
            try:
                data = r.json()
            except ValueError:
                ctx.error(f"xposedornot {email}: response is not JSON")
                continue
            if not isinstance(data, dict) or data.get("Error"):
                continue  # {"Error": "Not found"} means no exposure
            yield from parse_analytics(email, data)
