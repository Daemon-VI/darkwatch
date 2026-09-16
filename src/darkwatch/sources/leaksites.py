"""Ransomware and extortion leak sites, via the two public trackers that crawl them.

Gangs publish victims on onion "leak sites" to pressure them into paying. ransomware.live and
RansomLook crawl those sites and publish what they find. Matching a company against their data
answers "has anyone posted us on a leak site" without touching the gangs' infrastructure:

- ransomware.live `victims.json`: the full history (31,856 posts, 2013 to date, 21.7 MB on
  2026-09-16), downloaded once per `leak_feed_max_age_hours` and matched locally. Its per-term
  search API allows one request per minute, which is why the bulk file is used instead.
- RansomLook `/api/last/<days>`: the recent posts from a second, independent crawler.

Darkwatch deliberately does not fetch the gangs' claim pages. The tracker record already holds
the victim, group, dates and description; the onion URL is kept as evidence only.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from urllib.parse import quote

from ..cache import FeedCache
from ..config import Settings, Term, normalise
from . import Document, SourceContext, terms_present

log = logging.getLogger(__name__)

RANSOMWARE_LIVE_URL = "https://data.ransomware.live/victims.json"
RANSOMLOOK_URL = "https://www.ransomlook.io/api/last/{days}"


def validate_feed(body: bytes) -> None:
    """A usable tracker feed is a non-empty JSON list."""
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise ValueError(f"not JSON ({exc})") from exc
    if not isinstance(data, list) or not data:
        raise ValueError(f"expected a non-empty JSON list, got {type(data).__name__}")


def _s(value) -> str:
    return "" if value in (None, "None", "null") else str(value).strip()


def normalise_ransomware_live(rec: dict) -> dict:
    return {
        "tracker": "ransomware.live",
        "victim": _s(rec.get("post_title")),
        "group": _s(rec.get("group_name")),
        "discovered": _s(rec.get("discovered")),
        "published": _s(rec.get("published")),
        "website": _s(rec.get("website")),
        "country": _s(rec.get("country")),
        "sector": _s(rec.get("activity")),
        "description": _s(rec.get("description")),
        "post_url": _s(rec.get("post_url")),
    }


def normalise_ransomlook(rec: dict) -> dict:
    group = _s(rec.get("group_name"))
    return {
        "tracker": "RansomLook",
        "victim": _s(rec.get("post_title")),
        "group": group,
        "discovered": _s(rec.get("discovered")),
        "published": "",
        "website": "",
        "country": "",
        "sector": "",
        "description": _s(rec.get("description")),
        # RansomLook's `link` is a path on the gang's site, not a full URL
        "post_url": f"https://www.ransomlook.io/group/{group}" if group else "",
    }


def record_text(r: dict) -> str:
    parts = [
        f"{r['victim']} was listed on the leak site of the ransomware group {r['group']}",
        f" (seen by {r['tracker']}; discovered {r['discovered'] or 'unknown'}",
    ]
    if r["published"]:
        parts.append(f"; published {r['published']}")
    parts.append(").")
    for label, key in (("Website", "website"), ("Country", "country"), ("Sector", "sector")):
        if r[key]:
            parts.append(f" {label}: {r[key]}.")
    if r["description"]:
        parts.append(f" Listing text: {r['description']}")
    return "".join(parts)


def evidence_url(r: dict) -> str:
    """The post's own URL when the tracker has one. Otherwise a per-post identifier: the victim's
    website is not unique (trackers fill in placeholders like example.com), and one URL per post is
    what keeps two victims from collapsing into one hit."""
    if r["post_url"] and "ransomlook.io/group/" not in r["post_url"]:
        return r["post_url"]
    return f"leaksite:{quote(r['group'])}/{quote(r['victim'])}"


def merge_records(*feeds: list[dict]) -> list[dict]:
    """Merge tracker feeds, keeping one record per (victim, group); ransomware.live wins ties
    because its records carry the website and the claim URL."""
    seen: dict[tuple[str, str], dict] = {}
    for feed in feeds:
        for r in feed:
            if not r["victim"]:
                continue
            key = (normalise(r["victim"]), normalise(r["group"]))
            if key in seen:
                kept = seen[key]
                kept.setdefault("also_seen_by", set()).add(r["tracker"])
                continue
            seen[key] = r
    return list(seen.values())


def to_documents(records: list[dict], terms: list[Term]) -> Iterator[Document]:
    for r in records:
        # pre-filter on the tracker's own fields, never on our template wording, so a keyword
        # such as "ransomware" does not match every post
        raw = " ".join((r["victim"], r["website"], r["description"]))
        if not terms_present(raw, terms):
            continue
        text = record_text(r)
        also = sorted(r.get("also_seen_by", set()))
        yield Document(
            url=evidence_url(r),
            title=f"{r['group']} leak site: {r['victim']}",
            text=text,
            source="leaksite",
            signal_text=text,  # a post is short; read all of it, not 160 chars around the name
            evidence_date=r["published"] or r["discovered"],
            meta={
                "tracker": r["tracker"],
                "also_seen_by": also,
                "group": r["group"],
                "discovered": r["discovered"],
            },
        )


class LeakSiteSource:
    name = "leaksites"
    description = "ransomware / extortion leak-site posts (ransomware.live full history + RansomLook recent)"

    def unavailable_reason(self, settings: Settings) -> str:
        return ""

    def _load(self, ctx: SourceContext, cache: FeedCache, name: str, url: str, parse) -> list[dict]:
        s = ctx.settings
        ctx.progress(f"leaksites: loading {name}")
        try:
            feed = cache.get(
                name, url, ctx.clear, max_age_hours=s.leak_feed_max_age_hours, timeout=180,
                validate=validate_feed,
            )
        except Exception as exc:  # noqa: BLE001
            ctx.error(f"leaksites: {name} unavailable: {exc}")
            return []
        if feed.from_network:
            ctx.stats.requests += 1
        if feed.stale:
            ctx.error(f"leaksites: {name} refresh failed, used cached copy ({feed.note})")
        try:
            data = json.loads(feed.body)
        except ValueError as exc:
            ctx.error(f"leaksites: {name} is not valid JSON: {exc}")
            return []
        if not isinstance(data, list):
            ctx.error(f"leaksites: {name} has unexpected shape {type(data).__name__}")
            return []
        records = [parse(r) for r in data if isinstance(r, dict)]
        ctx.progress(f"leaksites: {name}: {len(records)} posts ({feed.note})")
        return records

    def discover(self, terms: list[Term], ctx: SourceContext) -> Iterator[Document]:
        s = ctx.settings
        cache = FeedCache(s.cache_dir)
        rl = self._load(ctx, cache, "ransomware_live_victims", RANSOMWARE_LIVE_URL, normalise_ransomware_live)
        look = self._load(
            ctx, cache, f"ransomlook_last_{s.ransomlook_days}",
            RANSOMLOOK_URL.format(days=s.ransomlook_days), normalise_ransomlook,
        )
        records = merge_records(rl, look)
        ctx.stats.note = f"{len(records)} unique posts checked"
        yield from to_documents(records, terms)
