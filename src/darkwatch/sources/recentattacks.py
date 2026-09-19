"""ransomware.live's recent cyber-attacks feed — incidents reported in the press or by the
victim, ahead of (or instead of) a gang posting them on a leak site.

The `leaksites` source answers "did a ransomware gang post this victim". This answers a wider
question: "was this organisation reported breached at all", including the many incidents a victim
discloses or a journalist covers before — or without — any gang claim. It is keyless clearnet
JSON, one bounded download per run, matched locally like the leak-site feed.

Each attack becomes a Document carrying the victim, domain, country and the disclosure summary as
signal text, so a watched company name or domain appearing in a recent incident is scored on what
the incident says, not on Darkwatch's own framing.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

from ..config import Settings, Term
from . import Document, SourceContext

log = logging.getLogger(__name__)

FEED = "https://api.ransomware.live/v2/recentcyberattacks"


def to_document(attack: dict) -> Document | None:
    victim = str(attack.get("victim") or attack.get("title") or "").strip()
    domain = str(attack.get("domain") or "").strip()
    if not victim and not domain:
        return None
    summary = str(attack.get("summary") or attack.get("description") or "").strip()
    country = str(attack.get("country") or "").strip()
    date = str(attack.get("date") or attack.get("added") or "").strip()
    gang = attack.get("claim_gang")
    link = str(attack.get("link") or attack.get("url") or attack.get("claim_url") or "").strip()
    lead = victim or domain
    if domain and domain not in lead:
        lead = f"{lead} ({domain})"  # the domain must be in the text, not only the signals, to match
    parts = [f"{lead} was reported in a cyber-attack"]
    if date:
        parts.append(f" ({date})")
    if country:
        parts.append(f", {country}")
    if isinstance(gang, str) and gang:
        parts.append(f"; claimed by {gang}")
    parts.append(". ")
    parts.append(summary)
    return Document(
        # a stable identity per incident, so a daily run does not re-report the same one
        url=link or f"ransomware.live:{domain or victim}:{date}",
        title=f"Reported cyber-attack: {victim or domain}",
        text="".join(parts),
        source="attack",
        signal_text=" ".join(p for p in (victim, domain, country, summary) if p),
        evidence_date=date,
        meta={"provider": "ransomware.live", "domain": domain, "has_infostealer": bool(attack.get("has_infostealer_info"))},
    )


class RecentAttacksSource:
    name = "recentattacks"
    description = "recently reported cyber-attacks and breaches, gang-claimed or not (ransomware.live, free, no key)"

    def unavailable_reason(self, settings: Settings) -> str:
        return ""

    def discover(self, terms: list[Term], ctx: SourceContext) -> Iterator[Document]:
        s = ctx.settings
        ctx.throttle("ransomware.live", max(s.delay_seconds, 1.0))
        ctx.progress("recentattacks: downloading the recent-attacks feed")
        try:
            r = ctx.clear.get(FEED, timeout=s.timeout)
            r.raise_for_status()
            data = r.json()
        except Exception as exc:  # noqa: BLE001
            ctx.error(f"recentattacks: feed download failed: {type(exc).__name__}")
            return
        attacks = data if isinstance(data, list) else []
        emitted = 0
        for attack in attacks:
            if not isinstance(attack, dict):
                continue
            doc = to_document(attack)
            if doc is not None:
                emitted += 1
                yield doc
        ctx.stats.note = f"{emitted} recent incident(s) checked"
