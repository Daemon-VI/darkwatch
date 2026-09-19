"""Source plugins. Each yields Documents (url, title, text) for the scanner to match against."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Protocol

import requests

from ..config import Settings, Term, deobfuscate, digits_only, normalise

log = logging.getLogger(__name__)

# Document.source values and what they mean. matcher.SOURCE_WEIGHT is keyed by these.
DOC_SOURCES = {
    "leaksite": "a ransomware / extortion group's leak site listing (via ransomware.live, RansomLook)",
    "attack": "a recently reported cyber-attack, gang-claimed or not (ransomware.live)",
    "telegram": "a public Telegram threat-actor or infostealer channel",
    "onion": "an onion page fetched over Tor",
    "ahmia-index": "Ahmia's stored title and description for an onion page",
    "stealer": "an infostealer-infected machine that had the identifier saved (Hudson Rock)",
    "breach": "a known data breach that included the identifier (XposedOrNot, HIBP, LeakCheck)",
    "paste": "a paste-site dump that included the identifier (XposedOrNot, HIBP)",
    "site": "a public profile page for a watched username (GitHub, Dev.to, ...)",
    "seed": "a page from the operator's seed list",
    "file": "a local file scanned with `darkwatch scan-text`",
}


@dataclass
class Document:
    url: str
    title: str
    text: str
    source: str  # one of DOC_SOURCES
    meta: dict = field(default_factory=dict)
    # When set, severity signals are read from this instead of the text around the match.
    # Structured sources use it to score on the data classes a breach exposed, not on prose.
    signal_text: str | None = None
    # When the exposure happened, if the source says (any string containing a year).
    evidence_date: str | None = None


@dataclass
class SourceStats:
    documents: int = 0
    hits: int = 0
    new_hits: int = 0
    requests: int = 0
    onion_fetches: int = 0
    onion_ok: int = 0
    seconds: float = 0.0
    errors: int = 0
    note: str = ""


@dataclass
class SourceContext:
    settings: Settings
    clear: requests.Session
    tor: requests.Session | None  # None when Tor is unavailable / disabled
    tor_ok: bool
    errors: list[str] = field(default_factory=list)
    progress: Callable[[str], None] = lambda msg: None
    stats: SourceStats = field(default_factory=SourceStats)
    onion_budget: int = 0
    _last_call: dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self.onion_budget = self.settings.max_onion_fetches

    def throttle(self, key: str, seconds: float | None = None) -> None:
        """Sleep so that calls tagged `key` are at least `seconds` apart."""
        gap = self.settings.delay_seconds if seconds is None else seconds
        last = self._last_call.get(key)
        if last is not None:
            wait = gap - (time.monotonic() - last)
            if wait > 0:
                time.sleep(wait)
        self._last_call[key] = time.monotonic()
        self.stats.requests += 1

    def take_onion_budget(self) -> bool:
        with self._lock:
            if self.onion_budget <= 0:
                return False
            self.onion_budget -= 1
            self.stats.onion_fetches += 1
            return True

    def error(self, msg: str) -> None:
        log.warning(msg)
        self.errors.append(msg)
        self.stats.errors += 1


class Source(Protocol):
    name: str
    description: str

    def discover(self, terms: list[Term], ctx: SourceContext) -> Iterator[Document]: ...

    def unavailable_reason(self, settings: Settings) -> str: ...


def terms_present(text: str, terms: list[Term]) -> list[Term]:
    """Terms whose needle occurs in `text` after normalisation. A cheap, permissive pre-filter;
    the matcher makes the real, boundary-aware decision."""
    norm = normalise(text)
    digits = None
    plain = None
    out = []
    for t in terms:
        needle = t.needle
        if not needle:
            continue
        if t.type == "phone":
            if digits is None:
                digits = digits_only(text)
            if needle in digits:
                out.append(t)
        elif needle in norm:
            out.append(t)
        elif t.type == "email":
            if plain is None:
                plain = normalise(deobfuscate(text))
            if needle in plain:
                out.append(t)
    return out


def registry() -> dict[str, Source]:
    from .ahmia import AhmiaSource
    from .hibp import HibpSource
    from .leakcheck import LeakCheckSource
    from .leaksites import LeakSiteSource
    from .recentattacks import RecentAttacksSource
    from .seeds import SeedSource
    from .sites import SiteSource
    from .stealers import StealerSource
    from .telegram import TelegramSource
    from .xposedornot import XposedOrNotSource

    sources: tuple[Source, ...] = (
        LeakSiteSource(),
        RecentAttacksSource(),
        StealerSource(),
        LeakCheckSource(),
        XposedOrNotSource(),
        HibpSource(),
        SiteSource(),
        TelegramSource(),
        AhmiaSource(),
        SeedSource(),
    )
    return {s.name: s for s in sources}
