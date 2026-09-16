"""Ahmia — a Tor search engine with an onion service, a clearnet front and an abuse filter.

What was observed on 2026-09-16, and what the source does about it:

- The search form carries a hidden per-page field (random name and value). Without it a search
  returns the landing page with zero results, so the token is read from the home page first.
- Search is a loose keyword match. An email query returned 1,319 listings that merely shared
  "gmail.com"; quoting a phrase changes nothing. So every returned listing is checked locally
  for the exact term (cheap, no network) instead of trusting the ranking.
- The same token + search flow works over Tor, both on Ahmia's onion service (309 results in
  1.5-9.5 s) and on ahmia.fi through an exit. A search is a list of the owner's identifiers,
  so with `ahmia_route: auto` it goes over Tor whenever Tor is verified, and never falls back to
  clearnet in that case. Clearnet is used only when the run has no Tor at all.

Two layers of evidence:
1. The listing (title + description Ahmia stored). Kept only when it contains the term.
2. The onion page itself, fetched over Tor as text. Fetched for every listing that contains the
   term, plus the `onion_fetch_top` best-ranked listings per query as a bounded check of page
   bodies, all within `max_onion_fetches` per run and `tor_workers` in parallel. When the page
   was fetched and the matcher finds the term on it, the listing is redundant and is dropped.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from urllib.parse import parse_qs, urlparse

import requests
from bs4 import BeautifulSoup

from ..config import Settings, Term, is_onion
from ..fetch import Page, fetch_text
from ..matcher import compile_term
from . import Document, SourceContext, terms_present

log = logging.getLogger(__name__)

AHMIA_ONION = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/"
AHMIA_CLEAR = "https://ahmia.fi/"
# Ahmia's own hosts: its results page links back to itself (time filters, pagination), and on
# the onion service those links are onion URLs. They must never be treated as search results.
AHMIA_HOSTS = {urlparse(AHMIA_ONION).hostname, urlparse(AHMIA_CLEAR).hostname}
# kept for callers that imported the old names
AHMIA_HOME = AHMIA_CLEAR
AHMIA_SEARCH = AHMIA_CLEAR + "search/"


def parse_search_form(html: str) -> dict[str, str]:
    """Hidden inputs of Ahmia's search form (the anti-bot token)."""
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form", id="searchForm") or soup.find("form", action="/search/")
    if form is None:
        return {}
    return {
        i.get("name"): i.get("value", "")
        for i in form.find_all("input", type="hidden")
        if i.get("name")
    }


def parse_ahmia_results(html: str) -> list[dict]:
    """(url, title, desc, last_seen) for each result on an Ahmia results page, in rank order."""
    soup = BeautifulSoup(html, "html.parser")
    results: list[dict] = []
    seen: set[str] = set()

    def add(url: str, title: str, desc: str, last_seen: str = "") -> None:
        url = url.strip()
        if not url or url in seen:
            return
        seen.add(url)
        results.append(
            {
                "url": url,
                "title": " ".join(title.split()),
                "desc": " ".join(desc.split()),
                "last_seen": last_seen,
            }
        )

    def resolve(href: str) -> str:
        if "redirect_url=" in href:
            qs = parse_qs(urlparse(href).query)
            return (qs.get("redirect_url") or [""])[0]
        return href

    for li in soup.select("li.result"):
        a = li.find("a", href=True)
        if not a:
            continue
        url = resolve(a["href"])
        if not url:
            cite = li.find("cite")
            url = cite.get_text(strip=True) if cite else ""
            if url and not url.startswith("http"):
                url = "http://" + url
        p = li.find("p")
        seen_at = li.find("span", class_="lastSeen")
        add(
            url,
            a.get_text(" ", strip=True),
            p.get_text(" ", strip=True) if p else "",
            (seen_at.get("data-timestamp", "") or seen_at.get_text(strip=True)) if seen_at else "",
        )

    if not results:  # fallback for changed markup: onion links that are not Ahmia's own pages
        for a in soup.find_all("a", href=True):
            url = resolve(a["href"])
            if is_onion(url) and urlparse(url).hostname not in AHMIA_HOSTS:
                add(url, a.get_text(" ", strip=True), "")
    return results


def plan_fetches(results: list[dict], terms: list[Term], top: int) -> list[tuple[dict, bool]]:
    """Which results to fetch: (result, listing_matched). Listing matches first, then the top N."""
    chosen: list[tuple[dict, bool]] = []
    picked: set[str] = set()
    for res in results:
        if is_onion(res["url"]) and terms_present(f"{res['title']} {res['desc']}", terms):
            chosen.append((res, True))
            picked.add(res["url"])
    for res in results[:top]:
        if is_onion(res["url"]) and res["url"] not in picked:
            chosen.append((res, False))
            picked.add(res["url"])
    return chosen


def search_routes(ctx: SourceContext) -> list[tuple[str, requests.Session]]:
    """(label, session) pairs to try for the Ahmia search, in order. Empty means: do not search."""
    mode = ctx.settings.ahmia_route
    tor_ready = ctx.tor is not None and ctx.tor_ok
    if mode == "clearnet" or (mode == "auto" and not tor_ready):
        return [("clearnet", ctx.clear)]
    if not tor_ready:
        return []  # mode "tor" without Tor: refuse rather than leak the identifiers
    return [("onion service", ctx.tor), ("ahmia.fi over Tor", ctx.tor)]


class AhmiaSource:
    name = "ahmia"
    description = "Ahmia onion search index (searched over Tor when available), then matching onion pages over Tor"

    def unavailable_reason(self, settings: Settings) -> str:
        if settings.ahmia_route == "tor":
            return "searches only run when Tor is verified (ahmia_route: tor)"
        return ""

    @staticmethod
    def _base(label: str) -> str:
        return AHMIA_ONION if label == "onion service" else AHMIA_CLEAR

    def _token(self, ctx: SourceContext, label: str, session: requests.Session) -> dict[str, str]:
        ctx.throttle(f"ahmia-{label}")
        r = session.get(self._base(label), timeout=ctx.settings.timeout)
        r.raise_for_status()
        tok = parse_search_form(r.text)
        if not tok:
            raise ValueError("search form has no hidden token; Ahmia's markup may have changed")
        return tok

    def _search_once(self, ctx: SourceContext, label: str, session: requests.Session, q: str,
                     token: dict[str, str]) -> tuple[str, dict[str, str]]:
        s = ctx.settings
        ctx.throttle(f"ahmia-{label}")
        url = self._base(label) + "search/"
        r = session.get(url, params={"q": q, **token}, timeout=s.timeout)
        r.raise_for_status()
        if 'class="result"' not in r.text and 'id="searchForm"' in r.text:
            # either no results or a rejected token; refresh the token once and retry
            token = self._token(ctx, label, session)
            ctx.throttle(f"ahmia-{label}")
            r = session.get(url, params={"q": q, **token}, timeout=s.timeout)
            r.raise_for_status()
        return r.text, token

    def _fetch(self, ctx: SourceContext, url: str) -> Page | None:
        assert ctx.tor is not None
        s = ctx.settings
        try:
            page = fetch_text(ctx.tor, url, timeout=s.timeout, max_bytes=s.max_page_bytes)
        except Exception as exc:  # noqa: BLE001 - one hostile page must not end the source
            log.warning("onion fetch crashed for %s: %s", url, type(exc).__name__)
            return None
        if page is not None and page.text:
            with ctx._lock:
                ctx.stats.onion_ok += 1
        return page

    def discover(self, terms: list[Term], ctx: SourceContext) -> Iterator[Document]:
        s = ctx.settings
        queries: dict[str, list[Term]] = {}
        for t in terms:
            queries.setdefault(t.value, []).append(t)
        routes = search_routes(ctx)
        if not routes:
            ctx.error("ahmia: skipped, ahmia_route is 'tor' and Tor is not verified")
            return
        patterns = {t: compile_term(t) for t in terms}
        tor_ready = ctx.tor is not None and ctx.tor_ok
        page_wait = s.timeout * 4 + 15  # fetch_text bounds a page at ~3x timeout plus connect time
        fetched: set[str] = set()
        page_terms: dict[str, set[str]] = {}  # url -> term values the matcher finds on the page
        route_idx = 0
        token: dict[str, str] | None = None
        listings_checked = 0
        dropped = 0

        pool = ThreadPoolExecutor(max_workers=max(1, s.tor_workers), thread_name_prefix="onion")
        try:
            for q, q_terms in queries.items():
                ctx.progress(f"ahmia: searching {q!r} via {routes[route_idx][0]}")
                html = None
                while route_idx < len(routes):
                    label, session = routes[route_idx]
                    try:
                        if token is None:
                            token = self._token(ctx, label, session)
                        html, token = self._search_once(ctx, label, session, q, token)
                        break
                    except (requests.RequestException, ValueError) as exc:
                        log.warning("ahmia via %s failed for %r: %s", label, q, type(exc).__name__)
                        route_idx += 1
                        token = None
                if html is None:
                    ctx.error(f"ahmia search failed for {q!r} on every route "
                              f"({', '.join(r[0] for r in routes)})")
                    route_idx = 0  # give the preferred route another chance on the next query
                    continue
                all_results = parse_ahmia_results(html)
                results = all_results[: s.max_results_per_term]
                if len(all_results) > len(results):
                    dropped += len(all_results) - len(results)
                    log.warning("ahmia %r: %d listings beyond max_results_per_term were not checked",
                                q, len(all_results) - len(results))
                listings_checked += len(results)
                plan = plan_fetches(results, q_terms, s.onion_fetch_top)
                matched_listing = {res["url"] for res, hit in plan if hit}
                log.info("ahmia %r: %d listings, %d contain the term", q, len(results), len(matched_listing))

                futures = {}
                if tor_ready:
                    for res, _hit in plan:
                        if res["url"] in fetched or not ctx.take_onion_budget():
                            continue
                        fetched.add(res["url"])
                        futures[res["url"]] = pool.submit(self._fetch, ctx, res["url"])
                    if futures:
                        ctx.progress(f"ahmia: fetching {len(futures)} onion page(s) over Tor for {q!r}")

                for res in results:
                    url = res["url"]
                    fut = futures.get(url)
                    if fut is not None:
                        try:
                            page = fut.result(timeout=page_wait)
                        except FutureTimeout:
                            log.warning("onion fetch still running after %ss, skipped: %s", page_wait, url)
                            page = None
                        if page is not None and page.text:
                            # remember which terms the matcher finds, not the page (memory is tight)
                            page_terms[url] = {t.value for t, rx in patterns.items() if rx.search(page.text)}
                            yield Document(
                                url=url,
                                title=page.title or res["title"],
                                text=page.text,
                                source="onion",
                                meta={"query": q, "status": page.status, "listing_matched": url in matched_listing},
                            )
                    present = page_terms.get(url, set())
                    if url in matched_listing and not any(t.value in present for t in q_terms):
                        yield Document(
                            url=url,
                            title=res["title"],
                            text=f"{res['title']} — {res['desc']}",
                            source="ahmia-index",
                            meta={"query": q, "last_seen": res.get("last_seen", "")},
                        )
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        note = [f"{listings_checked} listings checked via {routes[min(route_idx, len(routes) - 1)][0]}"]
        if dropped:
            note.append(f"{dropped} beyond max_results_per_term skipped")
        note.append(
            f"{ctx.stats.onion_ok}/{ctx.stats.onion_fetches} onion pages fetched" if tor_ready
            else "Tor off, no page fetches"
        )
        ctx.stats.note = "; ".join(note)
