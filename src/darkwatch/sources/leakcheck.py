"""LeakCheck's public API — which breaches hold an email *or a username*, and what they exposed.

Two things this adds that XposedOrNot and HIBP do not:

- It answers for usernames, not only addresses. A target whose strongest identifier is a handle
  had no breach coverage at all before.
- It names the data classes actually present (`ssn`, `dob`, `address`, `password`, `phone`), so
  severity is scored on what leaked rather than on the fact that something did.

Keyless and rate-limited; checked live 2026-09-18, where a clean address returns
`{"success": false, "error": "Not found"}`. The public tier returns the breach names and the
field list, never the values, which is all Darkwatch wants.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from urllib.parse import quote

from ..config import Settings, Term
from . import Document, SourceContext

log = logging.getLogger(__name__)

API = "https://leakcheck.io/api/public?check={value}"
MAX_LOOKUPS_PER_RUN = 20
MAX_SOURCES_PER_TERM = 25


def _fields_text(fields: list[str]) -> str:
    """The API's field names as the words the signal groups already know."""
    spelled = {
        "password": "passwords", "ssn": "social security", "dob": "date of birth",
        "address": "physical address", "phone": "phone numbers", "ip": "ip addresses",
        "first_name": "names", "last_name": "names", "username": "usernames",
    }
    return ", ".join(spelled.get(f, f.replace("_", " ")) for f in fields)


def parse(value: str, data: dict) -> list[Document]:
    if not data.get("success"):
        return []
    fields = [str(f) for f in (data.get("fields") or [])]
    classes = _fields_text(fields)
    found = data.get("found")
    sources = [s for s in (data.get("sources") or []) if isinstance(s, dict)]
    out: list[Document] = []
    for entry in sorted(sources, key=lambda s: str(s.get("date") or ""), reverse=True)[:MAX_SOURCES_PER_TERM]:
        name = str(entry.get("name") or "an unnamed breach")
        date = str(entry.get("date") or "")
        out.append(
            Document(
                url=f"leakcheck:{value}:{name}",
                title=f"Breach: {name}",
                text=(
                    f"{value} appears in the {name} breach"
                    + (f" ({date})" if date else "")
                    + f". Data exposed across the breaches holding this identifier: {classes or 'not stated'}."
                ),
                source="breach",
                # the field list is reported for the whole query, not per breach, so every
                # document from one lookup carries the same data classes
                signal_text=classes,
                evidence_date=date,
                meta={"provider": "LeakCheck", "breach": name, "records": found},
            )
        )
    return out


class LeakCheckSource:
    name = "leakcheck"
    description = "breaches holding each email or username, with the data classes exposed (LeakCheck, free, no key)"

    def unavailable_reason(self, settings: Settings) -> str:
        return ""

    def discover(self, terms: list[Term], ctx: SourceContext) -> Iterator[Document]:
        s = ctx.settings
        wanted = [t for t in terms if t.type in ("email", "username")]
        if len(wanted) > MAX_LOOKUPS_PER_RUN:
            ctx.error(f"leakcheck: {len(wanted)} identifiers; checking the first {MAX_LOOKUPS_PER_RUN}")
            wanted = wanted[:MAX_LOOKUPS_PER_RUN]
        checked = found = 0
        for term in wanted:
            ctx.throttle("leakcheck", max(s.delay_seconds, 2.0))
            ctx.progress(f"leakcheck: {term.value}")
            try:
                r = ctx.clear.get(API.format(value=quote(term.value, safe="")), timeout=s.timeout)
            except Exception as exc:  # noqa: BLE001
                ctx.error(f"leakcheck: lookup failed for {term.value}: {type(exc).__name__}")
                continue
            checked += 1
            if r.status_code == 429:
                ctx.error("leakcheck: rate limited (429); skipping the rest this run")
                break
            if not r.ok:
                ctx.error(f"leakcheck: {term.value}: HTTP {r.status_code}")
                continue
            try:
                data = r.json()
            except ValueError:
                ctx.error(f"leakcheck: {term.value}: response is not JSON")
                continue
            docs = parse(term.value, data if isinstance(data, dict) else {})
            if docs:
                found += 1
            yield from docs
        ctx.stats.note = f"{found}/{checked} identifier(s) found in breach data"
