"""Keyword search and aggregates over stored hits, and ad-hoc investigation of any keyword.

Two different things share this module because they answer the same question at two scales:

- `search_hits` searches what Darkwatch has already found. Every hit carries its term, title,
  URL, snippet and signals, and the dashboard needs to filter and rank across all of them.
  Plain tokenised LIKE is used rather than FTS5: a personal watchlist produces thousands of
  rows, not millions, and a LIKE scan over that is already sub-millisecond, with none of the
  index-sync failure modes an FTS shadow table brings.
- `investigate` searches the *sources* for a keyword that is not on the watchlist at all, so a
  one-off question ("is this domain being sold anywhere?") does not require editing the
  watchlist. Nothing it finds is written to the database; it is a look, not a monitor.
"""

from __future__ import annotations

import re
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .config import TERM_TYPES, Settings, Term, Watchlist
from .matcher import SEVERITIES, Matcher, severity_rank
from .sources import SourceContext, SourceStats, registry
from .storage import OPEN_STATUSES, STATUSES, Hit, Store
from .tor import check_tor, ensure_tor, make_session

# Columns a free-text query is matched against, in the order the UI shows them.
SEARCH_COLUMNS = ("term", "title", "url", "snippet", "signals", "target", "source", "term_type")
ORDERS = {
    "score": "score DESC, last_seen DESC, id DESC",
    "newest": "first_seen DESC, id DESC",
    "oldest": "first_seen ASC, id ASC",
    "seen": "last_seen DESC, id DESC",
    "target": "target ASC, score DESC",
}


def tokenise(query: str) -> list[str]:
    """Split a query into terms. Double quotes keep a phrase together."""
    out: list[str] = []
    for quoted, bare in re.findall(r'"([^"]*)"|(\S+)', query or ""):
        token = (quoted or bare).strip()
        if token:
            out.append(token)
    return out


@dataclass
class Page:
    hits: list[Hit]
    total: int
    took_ms: float
    query: str = ""


def _where(
    query: str,
    statuses: tuple[str, ...] | None,
    severities: tuple[str, ...] | None,
    sources: tuple[str, ...] | None,
    targets: tuple[str, ...] | None,
    term_types: tuple[str, ...] | None,
) -> tuple[str, list]:
    clauses: list[str] = []
    args: list = []
    for token in tokenise(query):
        like = f"%{token}%"
        ors = " OR ".join(f"{col} LIKE ? ESCAPE '\\'" for col in SEARCH_COLUMNS)
        clauses.append(f"({ors})")
        args.extend([like.replace("_", r"\_").replace("%%", "%%")] * len(SEARCH_COLUMNS))
    for column, values in (
        ("status", statuses), ("severity", severities), ("source", sources),
        ("target", targets), ("term_type", term_types),
    ):
        if values:
            clauses.append(f"{column} IN ({','.join('?' * len(values))})")
            args.extend(values)
    return (" AND ".join(clauses) if clauses else "1=1"), args


def search_hits(
    store: Store,
    query: str = "",
    *,
    statuses: tuple[str, ...] | None = OPEN_STATUSES,
    severities: tuple[str, ...] | None = None,
    sources: tuple[str, ...] | None = None,
    targets: tuple[str, ...] | None = None,
    term_types: tuple[str, ...] | None = None,
    order: str = "score",
    limit: int = 50,
    offset: int = 0,
) -> Page:
    """Hits matching every token in `query` (each token may match any column) and every filter."""
    started = time.perf_counter()
    where, args = _where(query, statuses, severities, sources, targets, term_types)
    total = store.conn.execute(f"SELECT COUNT(*) FROM hits WHERE {where}", args).fetchone()[0]
    sql = f"SELECT * FROM hits WHERE {where} ORDER BY {ORDERS.get(order, ORDERS['score'])} LIMIT ? OFFSET ?"
    rows = store.conn.execute(sql, [*args, max(1, min(limit, 500)), max(0, offset)]).fetchall()
    return Page(
        hits=[Hit.from_row(r) for r in rows],
        total=int(total),
        took_ms=round((time.perf_counter() - started) * 1000, 2),
        query=query,
    )


def facets(store: Store, statuses: tuple[str, ...] | None = None) -> dict[str, list[dict]]:
    """Counts per severity, source, status, target and term type, for the filter bar."""
    where, args = _where("", statuses, None, None, None, None)
    out: dict[str, list[dict]] = {}
    for key, column in (
        ("severity", "severity"), ("source", "source"), ("status", "status"),
        ("target", "target"), ("term_type", "term_type"),
    ):
        rows = store.conn.execute(
            f"SELECT {column} AS value, COUNT(*) AS n FROM hits WHERE {where} GROUP BY {column}", args
        ).fetchall()
        items = [{"value": r["value"], "count": r["n"]} for r in rows]
        if key == "severity":
            items.sort(key=lambda i: -severity_rank(i["value"]))
        else:
            items.sort(key=lambda i: -i["count"])
        out[key] = items
    return out


def timeline(store: Store, days: int = 30) -> list[dict]:
    """New hits per day for the last `days` days, oldest first, with gaps filled in."""
    rows = store.conn.execute(
        "SELECT substr(first_seen, 1, 10) AS day, severity, COUNT(*) AS n FROM hits"
        " WHERE first_seen >= date('now', ?) GROUP BY day, severity",
        (f"-{max(1, days)} days",),
    ).fetchall()
    by_day: dict[str, dict] = {}
    for r in rows:
        day = by_day.setdefault(r["day"], {"day": r["day"], "total": 0, **dict.fromkeys(SEVERITIES, 0)})
        day[r["severity"]] = day.get(r["severity"], 0) + r["n"]
        day["total"] += r["n"]
    filled = []
    cur = store.conn.execute("SELECT date('now', ?) AS d", (f"-{max(1, days) - 1} days",)).fetchone()["d"]
    today = store.conn.execute("SELECT date('now') AS d").fetchone()["d"]
    while cur <= today:
        filled.append(by_day.get(cur, {"day": cur, "total": 0, **dict.fromkeys(SEVERITIES, 0)}))
        cur = store.conn.execute("SELECT date(?, '+1 day') AS d", (cur,)).fetchone()["d"]
    return filled


def summary(store: Store) -> dict:
    """Everything the dashboard header shows, in one query pass."""
    open_page = search_hits(store, statuses=OPEN_STATUSES, limit=1)
    counts = {s: 0 for s in SEVERITIES}
    for row in store.conn.execute(
        f"SELECT severity, COUNT(*) n FROM hits WHERE status IN ({','.join('?' * len(OPEN_STATUSES))})"
        " GROUP BY severity", OPEN_STATUSES
    ):
        counts[row["severity"]] = row["n"]
    by_status = {s: 0 for s in STATUSES}
    by_status.update(store.counts())
    last = store.last_run()
    return {
        "open_hits": open_page.total,
        "by_severity": counts,
        "by_status": by_status,
        "targets": [r["target"] for r in store.conn.execute("SELECT DISTINCT target FROM hits ORDER BY target")],
        "last_run": dict(last) if last is not None else None,
        "total_hits": store.conn.execute("SELECT COUNT(*) FROM hits").fetchone()[0],
        "documents_seen": store.conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0],
    }


# --------------------------------------------------------------------------- ad-hoc investigation
@dataclass
class Finding:
    """One match from an investigation. Deliberately not a stored Hit: nothing is persisted."""

    term: str
    term_type: str
    source: str
    url: str
    title: str
    snippet: str
    signals: list[str]
    score: int
    severity: str

    def as_dict(self) -> dict:
        return {
            "term": self.term, "term_type": self.term_type, "source": self.source, "url": self.url,
            "title": self.title, "snippet": self.snippet, "signals": self.signals,
            "score": self.score, "severity": self.severity,
        }


@dataclass
class Investigation:
    query: str
    term_type: str
    sources: list[str]
    findings: list[Finding] = field(default_factory=list)
    documents: int = 0
    errors: list[str] = field(default_factory=list)
    stats: dict[str, dict] = field(default_factory=dict)
    seconds: float = 0.0
    tor: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "query": self.query, "term_type": self.term_type, "sources": self.sources,
            "findings": [f.as_dict() for f in self.findings], "documents": self.documents,
            "errors": self.errors, "stats": self.stats, "seconds": round(self.seconds, 1),
            "tor": self.tor,
        }


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")
PHONE_RE = re.compile(r"^[+()\d][\d\s\-().]{5,}$")


def guess_type(query: str) -> str:
    """What kind of identifier a raw query looks like, so it is matched the right way."""
    q = query.strip()
    if EMAIL_RE.match(q):
        return "email"
    if PHONE_RE.match(q) and len(re.sub(r"\D", "", q)) >= 6:
        return "phone"
    if DOMAIN_RE.match(q):
        return "domain"
    if " " in q:
        return "name"
    return "keyword"


def investigate(
    wl: Watchlist,
    query: str,
    *,
    term_type: str = "",
    sources: list[str] | None = None,
    use_tor: bool = True,
    progress: Callable[[str], None] = lambda m: None,
) -> Investigation:
    """Search the live sources for one keyword, without touching the watchlist or the database."""
    q = query.strip()
    if not q:
        raise ValueError("nothing to search for")
    kind = term_type or guess_type(q)
    if kind not in TERM_TYPES:
        raise ValueError(f"term type must be one of {', '.join(TERM_TYPES)}")
    settings: Settings = wl.settings
    wanted = sources or [s for s in settings.sources if s != "seeds"]
    reg = registry()
    unknown = [n for n in wanted if n not in reg]
    if unknown:
        raise ValueError(f"unknown sources {unknown}; available: {sorted(reg)}")

    term = Term(q if kind != "email" else q.lower(), kind, f"search:{q}")
    matcher = Matcher([term])
    result = Investigation(query=q, term_type=kind, sources=wanted)
    started = time.perf_counter()
    needs_tor = use_tor and "ahmia" in wanted
    clear = make_session(settings, via_tor=False)
    seen: set[tuple[str, str]] = set()

    with ensure_tor(settings, progress) if needs_tor else _nullctx() as tor_state:
        tor = None
        tor_ok = False
        if needs_tor and not (tor_state or {}).get("error"):
            tor = make_session(settings, via_tor=True)
            check = check_tor(tor, timeout=settings.timeout)
            tor_ok = bool(check["IsTor"])
            result.tor = {**(tor_state or {}), "is_tor": tor_ok, "exit_ip": check["IP"]}
            if not tor_ok and settings.require_tor:
                result.errors.append(f"Tor check failed: {check['error'] or 'not a Tor exit'}")
        elif needs_tor:
            result.tor = dict(tor_state or {})
            result.errors.append(f"Tor unavailable: {(tor_state or {}).get('error')}")

        for name in wanted:
            stats = SourceStats()
            ctx = SourceContext(
                settings=settings, clear=clear, tor=tor,
                tor_ok=tor_ok or (tor is not None and not settings.require_tor),
                progress=progress, stats=stats,
            )
            t0 = time.perf_counter()
            progress(f"search: {name}")
            try:
                for doc in reg[name].discover([term], ctx):
                    result.documents += 1
                    stats.documents += 1
                    best: dict[str, object] = {}
                    for m in matcher.find(
                        doc.text, source=doc.source, signal_text=doc.signal_text,
                        title=doc.title, evidence_date=doc.evidence_date, max_per_term=None,
                    ):
                        if not best or m.score > best["score"]:  # type: ignore[index]
                            best = {"score": m.score, "match": m}
                    if not best:
                        continue
                    m = best["match"]  # type: ignore[index]
                    key = (doc.source, doc.url)
                    if key in seen:
                        continue
                    seen.add(key)
                    stats.hits += 1
                    result.findings.append(
                        Finding(
                            term=q, term_type=kind, source=doc.source, url=doc.url, title=doc.title,
                            snippet=m.snippet, signals=m.signals, score=m.score, severity=m.severity,
                        )
                    )
            except Exception as exc:  # noqa: BLE001 - one source must not end the search
                ctx.error(f"source {name} crashed: {type(exc).__name__}: {exc}")
            stats.seconds = round(time.perf_counter() - t0, 1)
            result.errors.extend(ctx.errors)
            result.stats[name] = {
                "documents": stats.documents, "hits": stats.hits, "seconds": stats.seconds,
                "note": stats.note, "errors": stats.errors,
            }
    result.findings.sort(key=lambda f: (-severity_rank(f.severity), -f.score))
    result.seconds = time.perf_counter() - started
    return result


class _nullctx:
    def __enter__(self) -> dict:
        return {"managed": False, "bootstrap_seconds": None, "error": ""}

    def __exit__(self, *exc) -> None:
        return None


def hit_rows(store: Store, ids: list[int]) -> list[Hit]:
    if not ids:
        return []
    rows = store.conn.execute(
        f"SELECT * FROM hits WHERE id IN ({','.join('?' * len(ids))})", ids
    ).fetchall()
    return [Hit.from_row(r) for r in rows]


def as_dict(hit: Hit) -> dict:
    from .report import actions_for

    return {
        "id": hit.id, "target": hit.target, "term": hit.term, "term_type": hit.term_type,
        "source": hit.source, "url": hit.url, "title": hit.title, "snippet": hit.snippet,
        "signals": hit.signals, "score": hit.score, "severity": hit.severity,
        "first_seen": hit.first_seen, "last_seen": hit.last_seen, "status": hit.status,
        "note": hit.note, "actions": actions_for(hit),
    }


def sqlite_row_factory(conn: sqlite3.Connection) -> None:
    conn.row_factory = sqlite3.Row
