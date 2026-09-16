"""Person footprint — where a watched username exists on the public web.

For each `username` term, Darkwatch checks a list of sites that expose a profile at a
predictable URL (github.com/<user>, and so on). A profile that exists becomes a Document, so
the matcher then reads that profile page for the person's *other* watched identifiers too: a
real name or an email printed on a GitHub or about.me page is found and recorded against that
URL. That is the "scrape an individual's details" part — one handle leads to the pages that
carry the rest.

These are clearnet sites, so the checks go direct, not over Tor. A profile a person put up
themselves is public and expected, so a bare "exists here" scores LOW; it only rises if the
page itself carries breach or sale signals, or another identifier lands on it.

Detection is per site and conservative, to avoid claiming a profile that is not there:
- `missing_status` (404 by default): that status means the handle is free, so no hit.
- `absent_markers`: a soft-404 page returns 200 but contains one of these strings.
- Any other status (403, 429, 5xx, a login wall) is treated as "could not tell" and skipped.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import quote, urlparse

from ..config import Settings, Term
from ..fetch import fetch_text
from . import Document, SourceContext

log = logging.getLogger(__name__)

MAX_PROFILE_CHARS = 4000  # enough for other identifiers on the page; keeps the DB small


@dataclass(frozen=True)
class Site:
    name: str
    url: str  # contains {username}
    missing_status: int = 404
    absent_markers: tuple[str, ...] = ()

    def profile_url(self, username: str) -> str:
        return self.url.replace("{username}", quote(username, safe=""))


# Sites that serve a public profile as plain HTML/JSON (no JavaScript) and give a clean, verified
# signal for a missing handle. Checked against live responses on 2026-09-16 with handles known to
# exist and known not to: each of these returns 200 for a real handle and 404 (or a soft-404 with
# the marker below) for a free one. Sites that block non-browser requests (GitLab, npm, Reddit all
# 403) or soft-404 with 200 and no marker (PyPI, Telegram) are deliberately left out.
DEFAULT_SITES: tuple[Site, ...] = (
    Site("GitHub", "https://github.com/{username}"),
    Site("Dev.to", "https://dev.to/{username}"),
    Site("Keybase", "https://keybase.io/{username}"),
    Site("Replit", "https://replit.com/@{username}"),
    Site("Gravatar", "https://en.gravatar.com/{username}.json"),
    Site("Chess.com", "https://api.chess.com/pub/player/{username}"),
    Site(
        "Hacker News",
        "https://news.ycombinator.com/user?id={username}",
        missing_status=200,
        absent_markers=("No such user.",),
    ),
)


def build_sites(settings: Settings) -> list[Site]:
    sites: list[Site] = list(DEFAULT_SITES) if settings.person_site_builtins else []
    for tmpl in settings.person_sites:
        if "{username}" not in tmpl:
            continue  # validated at load time; belt and braces
        host = urlparse(tmpl).hostname or tmpl
        sites.append(Site(host, tmpl))
    return sites


def classify(status: int, text: str, site: Site) -> str:
    """'present', 'absent', or 'unknown'."""
    if status == site.missing_status and not site.absent_markers:
        return "absent"
    if status == 200:
        low = text.lower()
        if any(m.lower() in low for m in site.absent_markers):
            return "absent"
        return "present"
    if status == site.missing_status:
        return "absent"
    return "unknown"


class SiteSource:
    name = "sites"
    description = "public profiles for each username (GitHub, GitLab, Dev.to, PyPI, npm, ...), read over the clearnet"

    def unavailable_reason(self, settings: Settings) -> str:
        return "" if (settings.person_site_builtins or settings.person_sites) else "no sites configured"

    def discover(self, terms: list[Term], ctx: SourceContext) -> Iterator[Document]:
        s = ctx.settings
        usernames = sorted({t.value for t in terms if t.type == "username"})
        if not usernames:
            return
        sites = build_sites(s)
        checked = present = 0
        for username in usernames:
            for site in sites:
                url = site.profile_url(username)
                ctx.throttle(f"site-{urlparse(url).hostname}", s.delay_seconds)
                ctx.progress(f"sites: {site.name} / {username}")
                page = fetch_text(ctx.clear, url, timeout=s.timeout, max_bytes=s.max_page_bytes)
                checked += 1
                if page is None:
                    ctx.error(f"sites: {site.name} unreachable for {username}")
                    continue
                verdict = classify(page.status, page.text, site)
                if verdict != "present":
                    if verdict == "unknown":
                        log.info("sites: %s inconclusive for %s (HTTP %s)", site.name, username, page.status)
                    continue
                present += 1
                body = page.text[:MAX_PROFILE_CHARS]
                yield Document(
                    url=page.final_url,
                    title=f"{site.name} profile: {username}",
                    # the lead line guarantees the username is recorded; the page text lets the
                    # matcher find the person's other identifiers (real name, email) on it
                    text=f"Username {username} has a public profile on {site.name}. {body}",
                    source="site",
                    # a profile's own chrome ("session", "accounts", ...) is not a breach signal:
                    # score presence only, so a profile stays LOW unless another source says worse
                    signal_text="",
                    meta={"site": site.name, "username": username},
                )
        ctx.stats.note = f"{present}/{checked} profile checks matched across {len(sites)} site(s)"
