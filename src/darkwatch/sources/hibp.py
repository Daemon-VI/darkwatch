"""Have I Been Pwned.

Two lookups with different requirements:

- `GET /api/v3/breaches?domain=<domain>` — was the *service at this domain* itself breached.
  Free, no key. Run for every domain term, so company targets get this without configuration.
- `GET /api/v3/breachedaccount/<email>` and `/pasteaccount/<email>` — was this *address* in a
  breach or paste. Needs a paid key in DARKWATCH_HIBP_KEY; skipped (and said so) without one.
  XposedOrNot covers the same question for free, so the key is an upgrade, not a requirement.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from urllib.parse import quote

from ..config import Settings, Term
from . import Document, SourceContext

log = logging.getLogger(__name__)

API = "https://haveibeenpwned.com/api/v3"
DOMAIN_BREACHES = API + "/breaches?domain={domain}"
BREACHED = API + "/breachedaccount/{account}?truncateResponse=false"
PASTES = API + "/pasteaccount/{account}"


def domain_breach_document(domain: str, b: dict) -> Document:
    classes = ", ".join(b.get("DataClasses") or [])
    name = b.get("Name") or "unknown"
    return Document(
        url=f"https://haveibeenpwned.com/Breach/{quote(name)}",
        title=f"HIBP: {b.get('Title') or name} was breached",
        text=(
            f"The service at {domain} ({b.get('Title') or name}) was breached on "
            f"{b.get('BreachDate', '?')}: {b.get('PwnCount', 0):,} accounts. Exposed: {classes or 'not stated'}."
            + (" Marked sensitive." if b.get("IsSensitive") else "")
            + (" Unverified." if b.get("IsVerified") is False else "")
        ),
        source="breach",
        meta={"provider": "HIBP", "breach": name, "date": b.get("BreachDate")},
        signal_text=classes,
        evidence_date=b.get("BreachDate"),
    )


def account_breach_document(email: str, b: dict) -> Document:
    classes = ", ".join(b.get("DataClasses") or [])
    name = b.get("Name") or "unknown"
    return Document(
        url=f"https://haveibeenpwned.com/Breach/{quote(name)}",
        title=f"HIBP breach: {b.get('Title') or name}",
        text=(
            f"{email} is in the {b.get('Title') or name} breach ({b.get('Domain') or 'no domain'}, "
            f"{b.get('BreachDate', '?')}): {b.get('PwnCount', 0):,} accounts. Exposed: {classes or 'not stated'}."
        ),
        source="breach",
        meta={"provider": "HIBP", "breach": name, "date": b.get("BreachDate")},
        signal_text=classes,
        evidence_date=b.get("BreachDate"),
    )


def account_paste_document(email: str, p: dict) -> Document:
    return Document(
        url=f"hibp-paste:{p.get('Source')}/{p.get('Id')}",
        title=f"HIBP paste: {p.get('Title') or p.get('Id')}",
        text=(
            f"{email} appeared in a paste on {p.get('Source')} ({p.get('Date') or 'date unknown'}), "
            f"title {p.get('Title') or '-'}, {p.get('EmailCount', 0)} addresses in the paste."
        ),
        source="paste",
        meta={"provider": "HIBP", "paste": p.get("Id"), "date": p.get("Date")},
        signal_text="",
        evidence_date=p.get("Date"),
    )


class HibpSource:
    name = "hibp"
    description = "Have I Been Pwned: domain breaches (free) and per-email breaches/pastes (paid key)"

    def unavailable_reason(self, settings: Settings) -> str:
        return "" if settings.hibp_api_key else "per-email lookups need DARKWATCH_HIBP_KEY (domain lookups still run)"

    def discover(self, terms: list[Term], ctx: SourceContext) -> Iterator[Document]:
        s = ctx.settings
        ua = {"user-agent": "darkwatch/0.2"}
        for domain in sorted({t.value for t in terms if t.type == "domain"}):
            ctx.throttle("hibp", 1.6)
            ctx.progress(f"hibp: domain breaches for {domain}")
            try:
                r = ctx.clear.get(DOMAIN_BREACHES.format(domain=quote(domain)), headers=ua, timeout=s.timeout)
                r.raise_for_status()
                items = r.json()
            except Exception as exc:  # noqa: BLE001
                ctx.error(f"hibp domain lookup failed for {domain}: {exc}")
                continue
            for b in items or []:
                yield domain_breach_document(domain, b)

        emails = sorted({t.value for t in terms if t.type == "email"})
        if not emails:
            return
        if not s.hibp_api_key:
            ctx.progress("hibp: no DARKWATCH_HIBP_KEY, per-email lookups skipped (xposedornot covers them)")
            ctx.stats.note = "per-email lookups skipped: no key"
            return
        headers = {**ua, "hibp-api-key": s.hibp_api_key}
        for email in emails:
            for label, url in (("breach", BREACHED), ("paste", PASTES)):
                ctx.throttle("hibp", 6.5)  # the entry key tier allows 10 requests per minute
                ctx.progress(f"hibp: {label} lookup {email}")
                try:
                    r = ctx.clear.get(url.format(account=quote(email)), headers=headers, timeout=s.timeout)
                except Exception as exc:  # noqa: BLE001
                    ctx.error(f"hibp {label} lookup failed for {email}: {exc}")
                    continue
                if r.status_code == 404:
                    continue
                if r.status_code == 401:
                    ctx.error("hibp: API key rejected (401)")
                    return
                if r.status_code == 429:
                    ctx.error("hibp: rate limited (429); slow down or check the key tier")
                    continue
                if not r.ok:
                    ctx.error(f"hibp {label} {email}: HTTP {r.status_code}")
                    continue
                try:
                    items = r.json()
                except ValueError:
                    ctx.error(f"hibp {label} {email}: response is not JSON")
                    continue
                for item in items or []:
                    if label == "breach":
                        yield account_breach_document(email, item)
                    else:
                        yield account_paste_document(email, item)
