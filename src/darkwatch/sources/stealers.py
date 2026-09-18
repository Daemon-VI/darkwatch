"""Infostealer logs — machines infected with credential-stealing malware, via Hudson Rock.

This is the gap that mattered most. Leak sites and breach dumps answer "was a service you used
broken into". An infostealer answers something worse: a machine that *you* logged in from was
infected, and everything saved in that browser (passwords, cookies, session tokens) was taken
and sold. It is the dominant route for account takeover today, and no other Darkwatch source
sees it.

Hudson Rock's Cavalier OSINT endpoints are keyless and answer by email, username and domain
(checked live 2026-09-18; a clean address returns an explicit "not associated" message with an
empty `stealers` list, so negatives are unambiguous). The free tier masks the stolen values
themselves: passwords come back as `P********3`, the IP as `106.192.**.***`. Darkwatch keeps
those masked forms, which are enough to recognise the machine and act, and never asks for more.

One Document per infected machine, because each infection is a separate thing to deal with.
"""

from __future__ import annotations

import ast
import logging
from collections.abc import Iterator
from urllib.parse import quote

from ..config import Settings, Term
from . import Document, SourceContext

log = logging.getLogger(__name__)

BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
ENDPOINTS = {
    "email": BASE + "/search-by-email?email={value}",
    "username": BASE + "/search-by-username?username={value}",
    "domain": BASE + "/search-by-domain?domain={value}",
}
MAX_LOOKUPS_PER_RUN = 25
MAX_MACHINES_PER_TERM = 10


def _listish(value) -> list[str]:
    """The API returns Python-style list literals as strings: "['a', 'b']"."""
    if isinstance(value, list):
        return [str(v) for v in value if v]
    text = str(value or "").strip()
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = ast.literal_eval(text)
        except (ValueError, SyntaxError):
            return []
        return [str(v) for v in parsed if v]
    return [text] if text else []


def machine_document(value: str, kind: str, record: dict, index: int) -> Document:
    """One infected machine as evidence."""
    date = str(record.get("date_compromised") or "")
    computer = str(record.get("computer_name") or "an unnamed computer")
    corporate = int(record.get("total_corporate_services") or 0)
    user_services = int(record.get("total_user_services") or 0)
    passwords = _listish(record.get("top_passwords"))
    logins = _listish(record.get("top_logins"))

    parts = [
        f"{value} was saved on {computer}, a machine infected by an infostealer",
        f" (compromised {date or 'date unknown'}).",
        f" Credentials for {user_services} personal service(s)"
        + (f" and {corporate} corporate service(s)" if corporate else "")
        + " were taken from that machine's browser, including saved passwords and session cookies.",
    ]
    if record.get("operating_system"):
        parts.append(f" OS: {record['operating_system']}.")
    if record.get("malware_path"):
        parts.append(f" Malware path: {record['malware_path']}.")
    if record.get("antiviruses"):
        parts.append(f" Antivirus present: {', '.join(_listish(record['antiviruses'])) or 'none'}.")
    if record.get("ip"):
        parts.append(f" Masked IP: {record['ip']}.")
    if passwords:
        parts.append(f" Masked top passwords: {', '.join(passwords)}.")
    if logins:
        parts.append(f" Masked top logins: {', '.join(logins)}.")

    # An infostealer takes saved credentials by definition, so `credentials` is a fact about the
    # evidence, not a word found in prose. Corporate services mean someone can reach a network.
    signals = "passwords credentials cookies session tokens"
    if corporate:
        signals += " initial access vpn access rdp"
    return Document(
        # stable per infection, so re-running does not raise the same machine twice
        url=f"hudsonrock:{kind}:{value}:{date or index}",
        title=f"Infostealer infection: {computer}",
        text="".join(parts),
        source="stealer",
        signal_text=signals,
        evidence_date=date,
        meta={"provider": "Hudson Rock", "computer": computer, "corporate_services": corporate},
    )


def parse(value: str, kind: str, data: dict) -> list[Document]:
    stealers = data.get("stealers")
    if not isinstance(stealers, list) or not stealers:
        return []
    out = []
    for i, record in enumerate(stealers[:MAX_MACHINES_PER_TERM]):
        if isinstance(record, dict):
            out.append(machine_document(value, kind, record, i))
    return out


class StealerSource:
    name = "stealers"
    description = "infostealer infections that had this email, username or domain saved (Hudson Rock, free, no key)"

    def unavailable_reason(self, settings: Settings) -> str:
        return ""

    def discover(self, terms: list[Term], ctx: SourceContext) -> Iterator[Document]:
        s = ctx.settings
        wanted = [t for t in terms if t.type in ENDPOINTS]
        if len(wanted) > MAX_LOOKUPS_PER_RUN:
            ctx.error(f"stealers: {len(wanted)} identifiers; checking the first {MAX_LOOKUPS_PER_RUN}")
            wanted = wanted[:MAX_LOOKUPS_PER_RUN]
        checked = infected = 0
        for term in wanted:
            ctx.throttle("hudsonrock", max(s.delay_seconds, 1.5))
            ctx.progress(f"stealers: {term.type} {term.value}")
            try:
                r = ctx.clear.get(
                    ENDPOINTS[term.type].format(value=quote(term.value, safe="")), timeout=s.timeout
                )
            except Exception as exc:  # noqa: BLE001
                ctx.error(f"stealers: lookup failed for {term.value}: {type(exc).__name__}")
                continue
            checked += 1
            if r.status_code == 429:
                ctx.error("stealers: rate limited (429); skipping the rest this run")
                break
            if not r.ok:
                ctx.error(f"stealers: {term.value}: HTTP {r.status_code}")
                continue
            try:
                data = r.json()
            except ValueError:
                ctx.error(f"stealers: {term.value}: response is not JSON")
                continue
            docs = parse(term.value, term.type, data if isinstance(data, dict) else {})
            if docs:
                infected += 1
            yield from docs
        ctx.stats.note = f"{infected}/{checked} identifier(s) found in infostealer logs"
