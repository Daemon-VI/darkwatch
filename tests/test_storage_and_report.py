import json
import sqlite3

from darkwatch.report import (
    actions_for,
    prune_reports,
    to_html,
    to_json,
    to_markdown,
    write_reports,
)
from darkwatch.storage import OPEN_STATUSES, SCHEMA_VERSION, Store


def _hit(store, run_id, **kw):
    base = {
        "run_id": run_id, "target": "Acme", "term": "acme.com", "term_type": "domain", "source": "onion",
        "url": "http://abc.onion/x", "title": "leak", "snippet": "acme.com database dump for sale",
        "signals": ["sale"], "score": 6, "severity": "HIGH",
    }
    base.update(kw)
    return store.upsert_hit(**base)


RUN_INFO = {
    "run_id": 7, "sources": ["leaksites", "ahmia"], "tor_ok": True, "pages": 12, "new_hits": 1,
    "seen_hits": 2, "errors": ["e1"], "seconds": 42.5,
    "tor": {"used": True, "is_tor": True, "managed": True, "bootstrap_seconds": 15.2},
    "source_stats": {
        "leaksites": {"documents": 3, "hits": 3, "new_hits": 1, "onion_fetches": 0, "onion_ok": 0,
                      "seconds": 2.0, "note": "31856 unique posts checked"},
        "ahmia": {"documents": 9, "hits": 0, "new_hits": 0, "onion_fetches": 10, "onion_ok": 7,
                  "seconds": 40.1, "note": ""},
    },
}


def test_upsert_dedups_and_touches(tmp_path):
    s = Store(tmp_path / "db.sqlite3")
    run = s.start_run(["ahmia"])
    hid, new, _ = _hit(s, run)
    assert new
    hid2, new2, _ = _hit(s, run, snippet="ACME.COM   database dump for sale")  # whitespace/case differ
    assert not new2 and hid2 == hid
    assert len(s.hits()) == 1
    hid3, new3, _ = _hit(s, run, url="http://other.onion/")
    assert new3 and hid3 != hid
    s.finish_run(run, pages=2, new_hits=2, seen_hits=1, errors=[], info={"seconds": 1.5})
    last = s.last_run()
    assert last["new_hits"] == 2 and json.loads(last["info"]) == {"seconds": 1.5}
    s.close()


def test_last_run_skips_unfinished(tmp_path):
    with Store(tmp_path / "db.sqlite3") as s:
        done = s.start_run(["a"])
        s.finish_run(done, pages=0, new_hits=0, seen_hits=0, errors=[])
        s.start_run(["b"])  # still running
        assert s.last_run()["id"] == done
        assert s.last_run(finished_only=False)["id"] == done + 1
        assert len(s.runs()) == 2


def test_status_and_filters(tmp_path):
    s = Store(tmp_path / "db.sqlite3")
    run = s.start_run(["x"])
    hid, *_ = _hit(s, run)
    low, *_ = _hit(s, run, url="http://b.onion/", severity="LOW", score=1)
    fp, *_ = _hit(s, run, url="http://c.onion/")
    assert s.set_status([hid], "resolved", "rotated creds") == 1
    assert s.set_status([fp], "false_positive") == 1
    assert s.set_status([999], "resolved") == 0
    assert s.hits(status="resolved")[0].note == "rotated creds"
    assert [h.id for h in s.hits(statuses=OPEN_STATUSES)] == [low]
    assert [h.severity for h in s.hits(min_severity="HIGH")] == ["HIGH", "HIGH"]
    assert s.counts() == {"new": 1, "resolved": 1, "false_positive": 1}
    s.set_status([hid], "acknowledged")  # note kept when not given
    assert s.get(hid).note == "rotated creds"
    try:
        s.set_status([hid], "bogus")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    s.close()


def test_page_change_detection_per_source(tmp_path):
    s = Store(tmp_path / "db.sqlite3")
    assert s.record_page("u", "onion", "t", "hello") is True
    assert s.record_page("u", "onion", "t", "hello") is False
    assert s.record_page("u", "ahmia-index", "t", "listing") is True  # same URL, other source
    assert s.record_page("u", "onion", "t", "hello") is False  # not disturbed by the index entry
    assert s.record_page("u", "onion", "t", "changed") is True
    s.close()


def test_migrates_v01_database(tmp_path):
    db = tmp_path / "old.sqlite3"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, started TEXT NOT NULL, finished TEXT,
            sources TEXT NOT NULL, pages INTEGER DEFAULT 0, new_hits INTEGER DEFAULT 0,
            seen_hits INTEGER DEFAULT 0, errors TEXT DEFAULT '');
        CREATE TABLE pages (url TEXT PRIMARY KEY, title TEXT, text_sha256 TEXT, first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL, fetches INTEGER DEFAULT 1);
        INSERT INTO runs(started, sources, finished) VALUES ('2026-09-09', 'ahmia', '2026-09-09');
        INSERT INTO pages VALUES ('http://x.onion/', 'x', 'abc', '2026-09-09', '2026-09-09', 3);
        """
    )
    conn.commit()
    conn.close()
    with Store(db) as s:
        assert s.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        row = s.conn.execute("SELECT * FROM pages").fetchone()
        assert (row["url"], row["source"], row["fetches"]) == ("http://x.onion/", "unknown", 3)
        assert s.last_run()["info"] == "{}"
        assert s.record_page("http://x.onion/", "onion", "x", "new") is True
    with Store(db) as s:  # reopening is a no-op
        assert s.conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0] == 2


def test_actions_combine_source_type_and_signals(tmp_path):
    with Store(tmp_path / "db.sqlite3") as s:
        run = s.start_run(["x"])
        _hit(s, run, term="jane@acme.com", term_type="email", signals=["credentials", "sale"],
             severity="CRITICAL", score=8)
        _hit(s, run, url="leak", source="leaksite", signals=["sale", "access"])
        email_hit, leak_hit = sorted(s.hits(), key=lambda h: h.source != "onion")
    acts = actions_for(email_hit)
    assert any("Change the password of this mailbox" in a for a in acts)
    assert any("Preserve evidence" in a for a in acts)
    assert any("cybercrime.gov.in" in a for a in acts)
    assert len(acts) == len(set(acts))
    leak_acts = actions_for(leak_hit)
    assert leak_acts[0].startswith("Treat this as a live incident")
    assert any("CERT-In" in a for a in leak_acts)


def test_renderers(tmp_path):
    with Store(tmp_path / "db.sqlite3") as s:
        run = s.start_run(["x"])
        _hit(s, run, term="jane@acme.com", term_type="email", signals=["credentials"], severity="CRITICAL",
             score=8, title="<script>alert(1)</script>")
        hits = s.hits()
    md = to_markdown(hits, title="R", run_info=RUN_INFO)
    assert "[CRITICAL]" in md and "jane@acme.com" in md and "e1" in md
    assert "31856 unique posts checked" in md and "| ahmia | 9 | 0 | 0 | 7/10 | 40.1 |" in md
    assert "verified Tor exit; started by darkwatch, ready in 15.2s" in md
    html_out = to_html(hits, title="R <b>", run_info=RUN_INFO)
    assert "R &lt;b&gt;" in html_out and "&lt;script&gt;" in html_out and "<script>alert" not in html_out
    assert 'data-sev="CRITICAL"' in html_out
    assert "prefers-color-scheme:dark" in html_out
    empty = to_html([], title="R", run_info=None)
    assert "No open hits." in empty
    js = json.loads(to_json(hits, run_info=RUN_INFO))
    assert js["summary"]["CRITICAL"] == 1 and js["hits"][0]["actions"]


def test_tor_line_when_unused():
    info = {**RUN_INFO, "tor": {"used": False, "error": "nothing listening on 127.0.0.1:9050"}}
    assert "not used (nothing listening" in to_markdown([], title="R", run_info=info)


def test_write_reports_latest_and_prune(tmp_path):
    out = tmp_path / "reports"
    first = write_reports([], out, title="R", run_info=RUN_INFO)
    assert sorted(p.suffix for p in first) == [".html", ".json", ".md"]
    assert (out / "latest.html").read_text(encoding="utf-8") == first[1].read_text(encoding="utf-8")
    for i in range(4):
        stamp = f"20260101-00000{i}"
        for ext in ("md", "html", "json"):
            (out / f"darkwatch-{stamp}.{ext}").write_text("old")
    removed = prune_reports(out, keep=2)
    assert removed == 9  # 5 sets (4 old + the real one), keep the newest 2: 3 sets x 3 files
    remaining = {p.name.split(".")[0] for p in out.glob("darkwatch-*")}
    assert len(remaining) == 2
    assert first[0].name.split(".")[0] in remaining  # the real (newest) set survives
    assert (out / "latest.md").exists()


def test_hit_identity_ignores_snippet_and_keeps_strongest(tmp_path):
    with Store(tmp_path / "db.sqlite3") as s:
        run = s.start_run(["x"])
        hid, new, _ = _hit(s, run, snippet="views: 10 acme.com", score=4, severity="MEDIUM", signals=[])
        assert new
        # same page, counter changed, weaker: touched, evidence kept
        assert _hit(s, run, snippet="views: 11 acme.com", score=3, severity="MEDIUM", signals=[]) == (hid, False, False)
        assert s.get(hid).snippet == "views: 10 acme.com"
        # same page, stronger evidence: replaced, still not "new", status kept
        s.set_status([hid], "acknowledged")
        up = _hit(s, run, snippet="acme.com dump for sale", score=7, severity="CRITICAL")
        assert (up.is_new, up.escalated) == (False, True)
        h = s.get(hid)
        assert (h.snippet, h.severity, h.status) == ("acme.com dump for sale", "CRITICAL", "acknowledged")
        # same URL but different evidence type is a different hit
        assert _hit(s, run, source="ahmia-index")[1] is True


def test_migrates_v2_fingerprints(tmp_path):
    import hashlib

    db = tmp_path / "v2.sqlite3"
    with Store(db) as s:
        run = s.start_run(["x"])
        a, *_ = _hit(s, run)
        b, *_ = _hit(s, run, url="http://other.onion/")
    conn = sqlite3.connect(db)
    # emulate v2: snippet-based fingerprints, two rows for one (target, term, url, source)
    conn.execute("UPDATE hits SET fingerprint = 'old-' || id")
    conn.execute(
        "INSERT INTO hits(fingerprint, run_id, target, term, term_type, source, url, title, snippet, signals,"
        " score, severity, first_seen, last_seen, status, note) VALUES"
        " ('old-dup', 1, 'Acme', 'acme.com', 'domain', 'onion', 'http://abc.onion/x', 't', 'stronger', 'sale,access',"
        " 8, 'CRITICAL', '2026-09-01', '2026-09-15', 'resolved', 'handled')"
    )
    conn.execute("PRAGMA user_version = 2")
    conn.commit()
    conn.close()
    with Store(db) as s:
        rows = s.hits()
        assert sorted(h.id for h in rows) == [a, b]
        merged = s.get(a)
        assert (merged.snippet, merged.severity, merged.status, merged.note) == (
            "stronger", "CRITICAL", "resolved", "handled"
        )
        assert merged.last_seen == "2026-09-15" or merged.last_seen > "2026-09-15"
        fp = s.conn.execute("SELECT fingerprint FROM hits WHERE id=?", (a,)).fetchone()[0]
        assert fp == hashlib.sha1(b"Acme|acme.com|http://abc.onion/x|onion").hexdigest()


def test_escalation_reopens_resolved_but_not_false_positive(tmp_path):
    with Store(tmp_path / "db.sqlite3") as s:
        run = s.start_run(["x"])
        a = _hit(s, run, score=4, severity="MEDIUM", signals=[]).id
        b = _hit(s, run, url="http://b.onion/", score=4, severity="MEDIUM", signals=[]).id
        s.set_status([a], "resolved", "changed password")
        s.set_status([b], "false_positive", "not us")
        # stronger but same severity: evidence replaced, no escalation
        assert _hit(s, run, score=4, severity="MEDIUM").escalated is False
        up_a = _hit(s, run, score=8, severity="CRITICAL")
        up_b = _hit(s, run, url="http://b.onion/", score=8, severity="CRITICAL")
        assert up_a.escalated and not up_b.escalated
        ha, hb = s.get(a), s.get(b)
        assert ha.status == "new" and ha.note.startswith("changed password; reopened ")
        assert "from MEDIUM to CRITICAL" in ha.note
        assert (hb.status, hb.severity) == ("false_positive", "CRITICAL")


def test_migration_reopens_untriaged_stronger_duplicate(tmp_path):
    db = tmp_path / "v2b.sqlite3"
    with Store(db) as s:
        run = s.start_run(["x"])
        weak = _hit(s, run, score=4, severity="MEDIUM", signals=[]).id
        s.set_status([weak], "resolved", "handled")
    conn = sqlite3.connect(db)
    conn.execute("UPDATE hits SET fingerprint = 'old-weak'")
    conn.execute(
        "INSERT INTO hits(fingerprint, run_id, target, term, term_type, source, url, title, snippet, signals,"
        " score, severity, first_seen, last_seen, status, note) VALUES"
        " ('old-strong', 1, 'Acme', 'acme.com', 'domain', 'onion', 'http://abc.onion/x', 't', 'for sale', 'sale',"
        " 8, 'CRITICAL', '2026-09-02', '2026-09-15', 'new', '')"
    )
    conn.execute("PRAGMA user_version = 2")
    conn.commit()
    conn.close()
    with Store(db) as s:
        h = s.get(weak)
        assert (h.status, h.severity) == ("new", "CRITICAL")
        assert h.note == "handled; reopened on migration: evidence rose from MEDIUM to CRITICAL"
