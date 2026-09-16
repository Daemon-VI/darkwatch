"""SQLite persistence: runs, documents seen, and de-duplicated hits with a triage status.

Only snippets are stored, never full page bodies.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import NamedTuple, Self

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started TEXT NOT NULL,
    finished TEXT,
    sources TEXT NOT NULL,
    pages INTEGER DEFAULT 0,
    new_hits INTEGER DEFAULT 0,
    seen_hits INTEGER DEFAULT 0,
    errors TEXT DEFAULT '',
    info TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS pages (
    url TEXT NOT NULL,
    source TEXT NOT NULL,
    title TEXT,
    text_sha256 TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    fetches INTEGER DEFAULT 1,
    PRIMARY KEY (url, source)
);
CREATE TABLE IF NOT EXISTS hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT UNIQUE NOT NULL,
    run_id INTEGER NOT NULL,
    target TEXT NOT NULL,
    term TEXT NOT NULL,
    term_type TEXT NOT NULL,
    source TEXT NOT NULL,
    url TEXT NOT NULL,
    title TEXT,
    snippet TEXT NOT NULL,
    signals TEXT DEFAULT '',
    score INTEGER DEFAULT 0,
    severity TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    note TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS hits_status ON hits(status);
CREATE INDEX IF NOT EXISTS hits_target ON hits(target);
"""

STATUSES = ("new", "acknowledged", "resolved", "false_positive")
OPEN_STATUSES = ("new", "acknowledged")
SCHEMA_VERSION = 3


class Upsert(NamedTuple):
    id: int
    is_new: bool
    escalated: bool  # an existing hit whose severity rose; alert on it again


SEVERITY_ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 0


def _migrate(conn: sqlite3.Connection) -> None:
    """v0.1 databases (user_version 0) keyed pages by URL alone and had no runs.info."""
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version >= SCHEMA_VERSION:
        return
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "pages" in tables:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(pages)")]
        if "source" not in cols:
            conn.executescript(
                """
                ALTER TABLE pages RENAME TO pages_v1;
                CREATE TABLE pages (
                    url TEXT NOT NULL, source TEXT NOT NULL, title TEXT, text_sha256 TEXT,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, fetches INTEGER DEFAULT 1,
                    PRIMARY KEY (url, source)
                );
                INSERT INTO pages
                    SELECT url, 'unknown', title, text_sha256, first_seen, last_seen, fetches
                    FROM pages_v1;
                DROP TABLE pages_v1;
                """
            )
    if "runs" in tables:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(runs)")]
        if "info" not in cols:
            conn.execute("ALTER TABLE runs ADD COLUMN info TEXT DEFAULT '{}'")
    if "hits" in tables and version < 3:
        _refingerprint(conn)
    conn.commit()


def _refingerprint(conn: sqlite3.Connection) -> None:
    """v3 keys a hit by (target, term, url, source). Rows that now collide are merged into the
    oldest one, which keeps the most advanced triage status and the strongest evidence."""
    rank = {"new": 0, "acknowledged": 1, "resolved": 2, "false_positive": 3}
    groups: dict[str, list[sqlite3.Row]] = {}
    conn.row_factory = sqlite3.Row
    for row in conn.execute("SELECT * FROM hits ORDER BY id"):
        fp = fingerprint(row["target"], row["term"], row["url"], row["source"])
        groups.setdefault(fp, []).append(row)
    conn.execute("UPDATE hits SET fingerprint = 'migrating-' || id")
    for fp, rows in groups.items():
        keep = rows[0]
        best = max(rows, key=lambda r: r["score"])
        status_row = max(rows, key=lambda r: rank.get(r["status"], 0))
        status, note = status_row["status"], status_row["note"] or ""
        if status == "resolved" and _sev_rank(best["severity"]) > _sev_rank(status_row["severity"]):
            # the same rule upsert_hit applies at runtime: stronger evidence nobody triaged reopens
            status = "new"
            note = (note + "; " if note else "") + (
                f"reopened on migration: evidence rose from {status_row['severity']} to {best['severity']}"
            )
        conn.execute(
            "UPDATE hits SET fingerprint=?, snippet=?, signals=?, score=?, severity=?, status=?, note=?,"
            " last_seen=? WHERE id=?",
            (fp, best["snippet"], best["signals"], best["score"], best["severity"], status,
             note, max(r["last_seen"] for r in rows), keep["id"]),
        )
        for extra in rows[1:]:
            conn.execute("DELETE FROM hits WHERE id=?", (extra["id"],))


@dataclass
class Hit:
    id: int
    run_id: int
    target: str
    term: str
    term_type: str
    source: str
    url: str
    title: str
    snippet: str
    signals: list[str]
    score: int
    severity: str
    first_seen: str
    last_seen: str
    status: str
    note: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Hit:
        return cls(
            id=row["id"],
            run_id=row["run_id"],
            target=row["target"],
            term=row["term"],
            term_type=row["term_type"],
            source=row["source"],
            url=row["url"],
            title=row["title"] or "",
            snippet=row["snippet"],
            signals=[s for s in (row["signals"] or "").split(",") if s],
            score=row["score"],
            severity=row["severity"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            status=row["status"],
            note=row["note"] or "",
        )


def fingerprint(target: str, term: str, url: str, source: str) -> str:
    """One hit per identifier per piece of evidence. The snippet is deliberately not part of the
    key: pages with counters or rotating ads would otherwise raise a "new" hit on every run."""
    return hashlib.sha1(f"{target}|{term.lower()}|{url}|{source}".encode()).hexdigest()


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        _migrate(self.conn)
        self.conn.executescript(SCHEMA)
        self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # runs ------------------------------------------------------------------
    def start_run(self, sources: list[str]) -> int:
        cur = self.conn.execute(
            "INSERT INTO runs(started, sources) VALUES (?, ?)", (now_iso(), ",".join(sources))
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_run(
        self,
        run_id: int,
        *,
        pages: int,
        new_hits: int,
        seen_hits: int,
        errors: list[str],
        info: dict | None = None,
    ) -> None:
        self.conn.execute(
            "UPDATE runs SET finished=?, pages=?, new_hits=?, seen_hits=?, errors=?, info=? WHERE id=?",
            (now_iso(), pages, new_hits, seen_hits, "\n".join(errors), json.dumps(info or {}), run_id),
        )
        self.conn.commit()

    def last_run(self, finished_only: bool = True) -> sqlite3.Row | None:
        where = "WHERE finished IS NOT NULL" if finished_only else ""
        return self.conn.execute(f"SELECT * FROM runs {where} ORDER BY id DESC LIMIT 1").fetchone()

    def runs(self, limit: int = 20) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    # pages -----------------------------------------------------------------
    def record_page(self, url: str, source: str, title: str, text: str) -> bool:
        """Record a document. Returns True if its content changed since last time (or is new)."""
        sha = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        row = self.conn.execute(
            "SELECT text_sha256 FROM pages WHERE url=? AND source=?", (url, source)
        ).fetchone()
        ts = now_iso()
        if row is None:
            self.conn.execute(
                "INSERT INTO pages(url, source, title, text_sha256, first_seen, last_seen)"
                " VALUES (?,?,?,?,?,?)",
                (url, source, title, sha, ts, ts),
            )
            self.conn.commit()
            return True
        changed = row["text_sha256"] != sha
        self.conn.execute(
            "UPDATE pages SET title=?, text_sha256=?, last_seen=?, fetches=fetches+1"
            " WHERE url=? AND source=?",
            (title, sha, ts, url, source),
        )
        self.conn.commit()
        return changed

    # hits ------------------------------------------------------------------
    def upsert_hit(
        self,
        *,
        run_id: int,
        target: str,
        term: str,
        term_type: str,
        source: str,
        url: str,
        title: str,
        snippet: str,
        signals: list[str],
        score: int,
        severity: str,
    ) -> Upsert:
        """Insert a hit, or touch the existing one.

        An existing hit's evidence is replaced only by a stronger match (higher score), so a
        report always shows the worst thing seen at that URL. If that stronger match also raises
        the severity, the hit is *escalated*: it alerts again, and a resolved hit reopens. A hit
        marked false_positive never escalates; the owner has said it is not theirs.
        """
        fp = fingerprint(target, term, url, source)
        ts = now_iso()
        row = self.conn.execute(
            "SELECT id, score, severity, status, note FROM hits WHERE fingerprint=?", (fp,)
        ).fetchone()
        if row is not None:
            escalated = False
            if score > row["score"]:
                rises = _sev_rank(severity) > _sev_rank(row["severity"])
                escalated = rises and row["status"] != "false_positive"
                status, note = row["status"], row["note"] or ""
                if escalated and status == "resolved":
                    status = "new"
                    note = (note + "; " if note else "") + (
                        f"reopened {ts[:10]}: evidence rose from {row['severity']} to {severity}"
                    )
                self.conn.execute(
                    "UPDATE hits SET last_seen=?, title=?, snippet=?, signals=?, score=?, severity=?,"
                    " status=?, note=? WHERE id=?",
                    (ts, title, snippet, ",".join(signals), score, severity, status, note, row["id"]),
                )
            else:
                self.conn.execute("UPDATE hits SET last_seen=? WHERE id=?", (ts, row["id"]))
            self.conn.commit()
            return Upsert(int(row["id"]), False, escalated)
        cur = self.conn.execute(
            """INSERT INTO hits(fingerprint, run_id, target, term, term_type, source, url, title,
                                snippet, signals, score, severity, first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                fp, run_id, target, term, term_type, source, url, title, snippet,
                ",".join(signals), score, severity, ts, ts,
            ),
        )
        self.conn.commit()
        return Upsert(int(cur.lastrowid), True, False)

    def hits(
        self,
        *,
        status: str | None = None,
        statuses: tuple[str, ...] | None = None,
        target: str | None = None,
        run_id: int | None = None,
        min_severity: str | None = None,
    ) -> list[Hit]:
        sql = "SELECT * FROM hits WHERE 1=1"
        args: list = []
        if status:
            sql += " AND status=?"
            args.append(status)
        if statuses:
            sql += f" AND status IN ({','.join('?' * len(statuses))})"
            args.extend(statuses)
        if target:
            sql += " AND target=?"
            args.append(target)
        if run_id is not None:
            sql += " AND run_id=?"
            args.append(run_id)
        sql += " ORDER BY score DESC, first_seen DESC, id"
        rows = [Hit.from_row(r) for r in self.conn.execute(sql, args).fetchall()]
        if min_severity:
            from .matcher import severity_rank

            floor = severity_rank(min_severity)
            rows = [h for h in rows if severity_rank(h.severity) >= floor]
        return rows

    def get(self, hit_id: int) -> Hit | None:
        row = self.conn.execute("SELECT * FROM hits WHERE id=?", (hit_id,)).fetchone()
        return Hit.from_row(row) if row else None

    def set_status(self, hit_ids: list[int], status: str, note: str = "") -> int:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        n = 0
        for hid in hit_ids:
            cur = self.conn.execute(
                "UPDATE hits SET status=?, note=CASE WHEN ?='' THEN note ELSE ? END WHERE id=?",
                (status, note, note, hid),
            )
            n += cur.rowcount
        self.conn.commit()
        return n

    def counts(self) -> dict[str, int]:
        return {
            row["status"]: row["c"]
            for row in self.conn.execute("SELECT status, COUNT(*) c FROM hits GROUP BY status")
        }
