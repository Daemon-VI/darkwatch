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
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import quote, urlparse

import requests

from ..config import Settings, Term
from ..fetch import fetch_text
from . import Document, SourceContext

log = logging.getLogger(__name__)

MAX_PROFILE_CHARS = 4000  # enough for other identifiers on the page; keeps the DB small

_local = threading.local()


def _session(ctx: SourceContext) -> requests.Session:
    """A session private to the calling thread.

    `requests.Session` is not documented as thread-safe, and the profile checks are the one place
    Darkwatch fans out over the clearnet. Each worker gets its own session carrying the same
    headers as the shared one, so cookies and connection pools are never shared across threads.
    """
    if threading.current_thread() is threading.main_thread():
        return ctx.clear
    sess = getattr(_local, "session", None)
    if sess is None:
        sess = requests.Session()
        sess.headers.update(ctx.clear.headers)
        sess.proxies.update(ctx.clear.proxies)
        _local.session = sess
    return sess


@dataclass(frozen=True)
class Site:
    name: str
    url: str  # contains {username}
    missing_status: int = 404
    absent_markers: tuple[str, ...] = ()

    def profile_url(self, username: str) -> str:
        return self.url.replace("{username}", quote(username, safe=""))


# Sites that serve a public profile as plain HTML/JSON (no JavaScript) and give a clean, verified
# signal for a missing handle. Every entry was checked against live responses — the first seven on
# 2026-09-16, the rest on 2026-09-18 — by fetching a handle known to exist and one known to be free
# through Darkwatch's own fetcher and `classify()`: each returns "present" for the real handle and
# "absent" for the free one.
#
# Of 36 further candidates tested on 2026-09-18, 19 passed and 17 of those were not already here,
# which took the list from 7 to 24. The 17 that failed are deliberately absent, and they failed in
# three different ways:
#   - 200 for a free handle with no stable marker, so every handle would look like a profile:
#     Steam, Telegram, Twitch, Last.fm, ArtStation, Ko-fi, PyPI.
#   - a block or an error rather than an answer: GitLab and Letterboxd 403, Product Hunt 403,
#     Codeforces 400, Behance returns no text at all.
#   - 404 even for a handle that exists, because the real profile is behind a different path or
#     JavaScript: about.me, Bandcamp, Vimeo, Buy Me a Coffee, Goodreads.
DEFAULT_SITES: tuple[Site, ...] = (
    # code and technical
    Site("GitHub", "https://github.com/{username}"),
    Site("Dev.to", "https://dev.to/{username}"),
    Site("Replit", "https://replit.com/@{username}"),
    Site("Docker Hub", "https://hub.docker.com/v2/users/{username}/"),
    Site("Hugging Face", "https://huggingface.co/api/users/{username}/overview"),
    Site("npm", "https://www.npmjs.com/~{username}"),
    Site("Keybase", "https://keybase.io/{username}"),
    Site("Gravatar", "https://en.gravatar.com/{username}.json"),
    # social and publishing
    Site("X", "https://x.com/{username}"),
    Site("YouTube", "https://www.youtube.com/@{username}"),
    Site("Mastodon", "https://mastodon.social/api/v1/accounts/lookup?acct={username}"),
    Site("Tumblr", "https://{username}.tumblr.com"),
    Site("Substack", "https://{username}.substack.com"),
    Site("Linktree", "https://linktr.ee/{username}"),
    Site("Patreon", "https://www.patreon.com/{username}"),
    # creative
    Site("Dribbble", "https://dribbble.com/{username}"),
    Site("DeviantArt", "https://www.deviantart.com/{username}"),
    Site("Flickr", "https://www.flickr.com/people/{username}"),
    Site("SoundCloud", "https://soundcloud.com/{username}"),
    Site("itch.io", "https://itch.io/profile/{username}"),
    # games and hobbies
    Site("Chess.com", "https://api.chess.com/pub/player/{username}"),
    Site("Lichess", "https://lichess.org/api/user/{username}"),
    Site("MyAnimeList", "https://myanimelist.net/profile/{username}"),
    Site(
        "Hacker News",
        "https://news.ycombinator.com/user?id={username}",
        missing_status=200,
        absent_markers=("No such user.",),
    ),
)


def build_sites(settings: Settings) -> list[Site]:
    """The built-ins plus whatever the watchlist adds.

    A configured entry is a dict once the watchlist has been loaded, but a bare template is still
    accepted so `Settings(person_sites=[...])` works in code and in older watchlists.
    """
    sites: list[Site] = list(DEFAULT_SITES) if settings.person_site_builtins else []
    for entry in settings.person_sites:
        spec = {"url": entry} if isinstance(entry, str) else dict(entry)
        url = str(spec.get("url", ""))
        if "{username}" not in url:
            continue  # validated at load time; belt and braces
        sites.append(
            Site(
                name=str(spec.get("name") or urlparse(url).hostname or url),
                url=url,
                missing_status=int(spec.get("missing_status", 404)),
                absent_markers=tuple(spec.get("absent_markers") or ()),
            )
        )
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
    # Built from DEFAULT_SITES so it can never name a site the source does not actually check.
    description = (
        f"public profiles for each username across {len(DEFAULT_SITES)} sites ("
        + ", ".join(s.name for s in DEFAULT_SITES[:4])
        + f", +{len(DEFAULT_SITES) - 4} more), read over the clearnet"
    )

    def unavailable_reason(self, settings: Settings) -> str:
        return "" if (settings.person_site_builtins or settings.person_sites) else "no sites configured"

    def _check(self, site: Site, username: str, ctx: SourceContext) -> Document | None:
        """One profile check. Runs on a worker thread, so it touches nothing shared but `ctx`'s
        own thread-safe helpers and a session private to this thread."""
        s = ctx.settings
        url = site.profile_url(username)
        page = fetch_text(_session(ctx), url, timeout=s.timeout, max_bytes=s.max_page_bytes)
        if page is None:
            ctx.error(f"sites: {site.name} unreachable for {username}")
            return None
        verdict = classify(page.status, page.text, site)
        if verdict != "present":
            if verdict == "unknown":
                log.info("sites: %s inconclusive for %s (HTTP %s)", site.name, username, page.status)
            return None
        body = page.text[:MAX_PROFILE_CHARS]
        return Document(
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

    def discover(self, terms: list[Term], ctx: SourceContext) -> Iterator[Document]:
        s = ctx.settings
        usernames = sorted({t.value for t in terms if t.type == "username"})
        if not usernames:
            return
        sites = build_sites(s)
        checked = present = 0
        # Each site is a different host, so there is nothing to be polite about between them and
        # the whole list is one round of latency instead of two dozen. Handles are still done one
        # at a time, which keeps each host to one request at a time.
        workers = max(1, min(s.site_workers, len(sites)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="site") as pool:
            for index, username in enumerate(usernames):
                if index:
                    # every host is about to be asked a second time; one gap covers all of them
                    time.sleep(s.delay_seconds)
                ctx.progress(f"sites: {len(sites)} site(s) for {username}")
                docs = list(pool.map(lambda site, u=username: self._check(site, u, ctx), sites))
                checked += len(sites)
                ctx.stats.requests += len(sites)
                for doc in docs:
                    if doc is not None:
                        present += 1
                        yield doc
        ctx.stats.note = f"{present}/{checked} profile checks matched across {len(sites)} site(s)"
