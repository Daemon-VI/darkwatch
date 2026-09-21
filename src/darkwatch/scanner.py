"""The run loop: (managed) Tor -> sources -> documents -> matcher -> store.

One broken source never ends the run: its exception is recorded against it and the next source
starts. Everything measurable about the run (per-source documents, hits, requests, onion fetch
success, seconds; Tor bootstrap time and exit check) goes into `RunResult.info` and the runs table,
so the report can say what was actually searched rather than what was configured.
"""

from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field, replace

from .config import Settings, Watchlist
from .matcher import Match, Matcher
from .sources import Document, SourceContext, SourceStats, registry
from .storage import Hit, Store
from .tor import check_tor, ensure_tor, make_session

log = logging.getLogger(__name__)


@dataclass
class RunResult:
    run_id: int
    sources: list[str]
    tor_ok: bool
    tor_info: dict
    pages: int = 0
    new_hits: list[Hit] = field(default_factory=list)
    escalated_hits: list[Hit] = field(default_factory=list)
    seen_hits: int = 0
    errors: list[str] = field(default_factory=list)
    source_stats: dict[str, SourceStats] = field(default_factory=dict)
    seconds: float = 0.0

    @property
    def alertable(self) -> list[Hit]:
        """New hits plus known hits whose severity rose this run."""
        return self.new_hits + self.escalated_hits

    def info(self) -> dict:
        return {
            "tor": self.tor_info,
            "seconds": round(self.seconds, 1),
            "source_stats": {k: asdict(v) for k, v in self.source_stats.items()},
        }

    def run_info(self) -> dict:
        """The dict the report renderers take."""
        return {
            "run_id": self.run_id,
            "sources": self.sources,
            "tor_ok": self.tor_ok,
            "pages": self.pages,
            "new_hits": len(self.new_hits),
            "escalated_hits": len(self.escalated_hits),
            "seen_hits": self.seen_hits,
            "errors": self.errors,
            **self.info(),
        }


def scan_documents(
    docs: Iterable[Document],
    matcher: Matcher,
    store: Store,
    run_id: int,
    result: RunResult,
    stats: SourceStats | None = None,
) -> None:
    stats = stats if stats is not None else SourceStats()
    for doc in docs:
        result.pages += 1
        stats.documents += 1
        store.record_page(doc.url, doc.source, doc.title, doc.text)
        best: dict[tuple[str, str, str], Match] = {}
        for m in matcher.find(
            doc.text, source=doc.source, signal_text=doc.signal_text,
            title=doc.title, evidence_date=doc.evidence_date,
            max_per_term=None,  # the strongest occurrence may be the 50th on a forum page
        ):
            key = (m.term.target, m.term.type, m.term.value)
            if key not in best or m.score > best[key].score:
                best[key] = m
        for m in best.values():
            stats.hits += 1
            up = store.upsert_hit(
                run_id=run_id,
                target=m.term.target,
                term=m.term.value,
                term_type=m.term.type,
                source=doc.source,
                url=doc.url,
                title=doc.title,
                snippet=m.snippet,
                signals=m.signals,
                score=m.score,
                severity=m.severity,
            )
            if up.is_new:
                stats.new_hits += 1
                h = store.get(up.id)
                if h is not None:
                    result.new_hits.append(h)
            else:
                result.seen_hits += 1
                if up.escalated:
                    h = store.get(up.id)
                    if h is not None:
                        result.escalated_hits.append(h)


def deepen(settings: Settings) -> Settings:
    """A copy of `settings` tuned for a deep scan: every source, no channel cap, far more onion
    pages, and links followed one level from a matched onion page. It only raises limits, so a
    watchlist that already sets something higher is left alone."""
    from .config import ALL_SOURCES

    return replace(
        settings,
        sources=list(ALL_SOURCES),
        telegram_max_channels=0,
        # Every listing that *contains* a term is fetched regardless (bounded only by the budget
        # below), and matched pages are then followed one level. The blind top-N is only a
        # secondary sweep for a term that appears in a page body but not its Ahmia listing, so it
        # is raised modestly: onion fetches hang ~20-35% of the time and each hang costs up to the
        # ~195 s page deadline, so a top of 50 spent the whole run timing out on pages nothing
        # matched. 15 broadens the sweep without turning the run into a wall of timeouts.
        onion_fetch_top=max(15, settings.onion_fetch_top),
        max_onion_fetches=max(2000, settings.max_onion_fetches),
        onion_link_depth=max(1, settings.onion_link_depth),
    )


def run_scan(
    wl: Watchlist,
    *,
    sources: list[str] | None = None,
    use_tor: bool = True,
    progress: Callable[[str], None] = lambda m: None,
) -> RunResult:
    started = time.monotonic()
    s = wl.settings
    wanted = sources or s.sources
    reg = registry()
    unknown = [n for n in wanted if n not in reg]
    if unknown:
        raise ValueError(f"unknown sources {unknown}; available: {sorted(reg)}")
    needs_tor = use_tor and any(n in ("ahmia", "seeds") for n in wanted)  # sites is clearnet

    store = Store(s.db_path)
    run_id = store.start_run(wanted)
    result = RunResult(run_id=run_id, sources=wanted, tor_ok=False, tor_info={"used": False})
    terms = wl.terms()
    matcher = Matcher(terms)
    clear = make_session(s, via_tor=False)
    try:
        with _maybe_tor(s, needs_tor, progress) as tor_state:
            tor = None
            if needs_tor and not tor_state.get("error"):
                tor = make_session(s, via_tor=True)
                progress(f"tor: checking the exit via {s.tor_proxy}")
                check = check_tor(tor, timeout=s.timeout)
                result.tor_ok = bool(check["IsTor"])
                result.tor_info = {**tor_state, "used": True, "is_tor": check["IsTor"],
                                   "exit_ip": check["IP"], "check_error": check["error"]}
                if not result.tor_ok:
                    why = check["error"] or "not a Tor exit"
                    if s.require_tor:
                        progress(f"tor: exit check failed ({why}); onion fetches off")
                        result.errors.append(f"Tor check failed ({why}); onion fetches skipped")
                    else:
                        progress(f"tor: exit check failed ({why}); require_tor is false, fetching anyway")
                        result.errors.append(f"Tor check failed ({why}); onion fetches ran unverified")
            elif needs_tor:
                result.tor_info = {**tor_state, "used": False}
                result.errors.append(f"Tor unavailable: {tor_state['error']}")

            for name in wanted:
                src = reg[name]
                stats = SourceStats()
                result.source_stats[name] = stats
                ctx = SourceContext(
                    settings=s, clear=clear, tor=tor,
                    tor_ok=result.tor_ok or (tor is not None and not s.require_tor),
                    progress=progress, stats=stats,
                )
                t0 = time.monotonic()
                progress(f"source {name}: start")
                try:
                    scan_documents(src.discover(terms, ctx), matcher, store, run_id, result, stats)
                except Exception as exc:
                    log.exception("source %s crashed", name)
                    ctx.error(f"source {name} crashed: {type(exc).__name__}: {exc}")
                stats.seconds = round(time.monotonic() - t0, 1)
                result.errors.extend(ctx.errors)
                progress(
                    f"source {name}: {stats.documents} docs, {stats.new_hits} new hits, "
                    f"{stats.seconds}s" + (f" ({stats.note})" if stats.note else "")
                )
    finally:
        result.seconds = time.monotonic() - started
        store.finish_run(
            run_id,
            pages=result.pages,
            new_hits=len(result.new_hits),
            seen_hits=result.seen_hits,
            errors=result.errors,
            info=result.info(),
        )
        store.close()
    return result


def _maybe_tor(settings, needed: bool, progress):
    if needed:
        return ensure_tor(settings, progress)
    return contextlib.nullcontext({"managed": False, "bootstrap_seconds": None, "error": "not needed"})
