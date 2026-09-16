"""Seed URLs — pages you choose to re-scan every run (leak-listing sites, forums, paste mirrors).

Follows same-host links one level deep, capped by `max_seed_pages`. Every hop, including
redirects, is routed by hostname: `.onion` goes over Tor (only when Tor is usable), everything
else goes direct. Nothing is shipped in the default list on purpose: which sites are worth
watching depends on the target, and an operator should add them knowingly. One broken page
never ends the source.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..config import Settings, Term, is_onion
from ..fetch import fetch_text
from . import Document, SourceContext

log = logging.getLogger(__name__)


def same_host_links(base_url: str, hrefs: list[str]) -> list[str]:
    host = urlparse(base_url).netloc
    out = []
    for href in hrefs:
        u = urljoin(base_url, href)
        p = urlparse(u)
        if p.scheme in ("http", "https") and p.netloc == host:
            out.append(u.split("#")[0])
    return out


class SeedSource:
    name = "seeds"
    description = "operator-listed onion / clearnet pages, same-host links one level deep"

    def unavailable_reason(self, settings: Settings) -> str:
        return "" if settings.seeds else "no seeds configured"

    def discover(self, terms: list[Term], ctx: SourceContext) -> Iterator[Document]:
        s = ctx.settings
        if not s.seeds:
            return
        tor_ready = ctx.tor is not None and ctx.tor_ok

        def route(url: str):
            if is_onion(url):
                return ctx.tor if tor_ready else None
            return ctx.clear

        queue: list[tuple[str, int]] = [(u, 0) for u in s.seeds]
        seen: set[str] = set()
        while queue and len(seen) < s.max_seed_pages:
            url, depth = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            onion = is_onion(url)
            if onion and not tor_ready:
                ctx.error(f"seed {url} skipped: Tor not available")
                continue
            if onion and not ctx.take_onion_budget():
                ctx.error(f"seed {url} skipped: max_onion_fetches reached")
                continue
            ctx.throttle("tor-fetch" if onion else "seed-clear")
            ctx.progress(f"seeds: fetching {url}")
            try:
                page = fetch_text(
                    None, url, timeout=s.timeout, max_bytes=s.max_page_bytes, route=route, keep_html=True,
                )
                if page is None:
                    ctx.error(f"seed {url}: unavailable, not text, or redirected somewhere unsafe")
                    continue
                if onion:
                    ctx.stats.onion_ok += 1
                if depth < 1 and page.html:
                    soup = BeautifulSoup(page.html, "html.parser")
                    hrefs = [a["href"] for a in soup.find_all("a", href=True)]
                    for link in same_host_links(page.final_url, hrefs):
                        if link not in seen:
                            queue.append((link, depth + 1))
            except Exception as exc:  # noqa: BLE001 - one hostile page must not end the source
                ctx.error(f"seed {url} failed: {type(exc).__name__}: {exc}")
                continue
            if page.text:
                yield Document(
                    url=url, title=page.title, text=page.text, source="seed",
                    meta={"depth": depth, "final_url": page.final_url},
                )
