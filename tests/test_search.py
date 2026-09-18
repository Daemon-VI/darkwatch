"""Keyword search over stored findings, and ad-hoc investigation of a keyword."""

from __future__ import annotations

import pytest

from darkwatch.config import Settings, Target, Watchlist
from darkwatch.search import (
    Finding,
    facets,
    guess_type,
    investigate,
    search_hits,
    summary,
    timeline,
    tokenise,
)
from darkwatch.sources import Document, SourceStats
from darkwatch.storage import OPEN_STATUSES, Store


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "db.sqlite3") as s:
        run = s.start_run(["x"])
        rows = [
            ("Acme", "acme.com", "domain", "leaksite", "http://gang.onion/acme", "lockbit: Acme",
             "Acme Corp listed, 200GB of invoices", ["sale"], 8, "CRITICAL"),
            ("Acme", "Acme Corp", "name", "onion", "http://forum.onion/t1", "Leaks forum",
             "selling Acme Corp database with passwords", ["credentials", "sale"], 6, "HIGH"),
            ("Jane", "jane@mail.example", "email", "breach", "https://hibp/Canva", "HIBP: Canva",
             "jane@mail.example is in the Canva breach", ["credentials"], 5, "HIGH"),
            ("Jane", "jane@mail.example", "email", "paste", "https://paste/1", "Paste on Pastebin",
             "jane@mail.example appeared in a paste", [], 4, "MEDIUM"),
            ("Jane", "janedoe", "username", "site", "https://github.com/janedoe", "GitHub profile",
             "Username janedoe has a public profile", [], 1, "LOW"),
        ]
        for target, term, term_type, source, url, title, snippet, signals, score, sev in rows:
            s.upsert_hit(run_id=run, target=target, term=term, term_type=term_type, source=source,
                         url=url, title=title, snippet=snippet, signals=signals, score=score,
                         severity=sev)
        s.finish_run(run, pages=5, new_hits=5, seen_hits=0, errors=[], info={"seconds": 3.0})
        yield s


def test_tokenise_keeps_phrases():
    assert tokenise('acme "for sale" jane') == ["acme", "for sale", "jane"]
    assert tokenise("   ") == []


def test_search_matches_any_column_and_ands_tokens(store):
    assert search_hits(store, "acme").total == 2
    assert search_hits(store, "canva").total == 1  # title only
    assert search_hits(store, "invoices").total == 1  # snippet only
    assert search_hits(store, "github.com").total == 1  # url only
    assert search_hits(store, "acme passwords").total == 1  # both tokens must match
    assert search_hits(store, "acme nonsense").total == 0
    assert search_hits(store, '"200GB of invoices"').total == 1
    assert search_hits(store, "ACME").total == 2  # case-insensitive


def test_search_filters_and_order(store):
    assert search_hits(store, severities=("CRITICAL",)).total == 1
    assert search_hits(store, sources=("breach", "paste")).total == 2
    assert search_hits(store, targets=("Jane",)).total == 3
    assert search_hits(store, term_types=("email",)).total == 2
    worst = search_hits(store, order="score").hits
    assert [h.severity for h in worst][:2] == ["CRITICAL", "HIGH"]
    by_target = search_hits(store, order="target").hits
    assert by_target[0].target == "Acme"


def test_search_paginates(store):
    first = search_hits(store, limit=2, offset=0)
    second = search_hits(store, limit=2, offset=2)
    assert first.total == second.total == 5
    assert len(first.hits) == len(second.hits) == 2
    assert {h.id for h in first.hits}.isdisjoint({h.id for h in second.hits})
    assert first.took_ms >= 0


def test_search_respects_status(store):
    ids = [h.id for h in search_hits(store).hits if h.severity == "LOW"]
    store.set_status(ids, "false_positive")
    assert search_hits(store).total == 4  # open only by default
    assert search_hits(store, statuses=None).total == 5
    assert search_hits(store, statuses=("false_positive",)).total == 1


def test_facets_and_summary_and_timeline(store):
    f = facets(store, OPEN_STATUSES)
    assert [i["value"] for i in f["severity"]] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert {i["value"] for i in f["source"]} == {"leaksite", "onion", "breach", "paste", "site"}
    assert {i["value"]: i["count"] for i in f["target"]} == {"Jane": 3, "Acme": 2}

    s = summary(store)
    assert s["open_hits"] == 5 and s["by_severity"]["CRITICAL"] == 1
    assert s["targets"] == ["Acme", "Jane"] and s["last_run"]["pages"] == 5

    days = timeline(store, days=7)
    assert len(days) == 7
    assert sum(d["total"] for d in days) == 5  # all created today
    assert days[-1]["CRITICAL"] == 1


@pytest.mark.parametrize(("query", "kind"), [
    ("jane@mail.example", "email"),
    ("+91 98765 43210", "phone"),
    ("9876543210", "phone"),
    ("example.com", "domain"),
    ("sub.example.co.uk", "domain"),
    ("Jane Doe", "name"),
    ("night_owl", "keyword"),
    ("lockbit", "keyword"),
])
def test_guess_type(query, kind):
    assert guess_type(query) == kind


def test_investigate_runs_sources_without_storing(tmp_path, monkeypatch):
    seen = {}

    class Fake:
        name = "leaksites"
        description = "fake"

        def unavailable_reason(self, settings):
            return ""

        def discover(self, terms, ctx):
            seen["terms"] = [(t.value, t.type, t.target) for t in terms]
            ctx.stats.note = "2 posts"
            yield Document(url="http://gang.onion/x", title="lockbit: Widgets Ltd",
                           text="Widgets Ltd was listed. Website: widgets.example. 40GB of payroll",
                           source="leaksite", signal_text="40GB of payroll and bank accounts")
            yield Document(url="http://gang.onion/y", title="other", text="nothing here", source="leaksite")

    monkeypatch.setattr("darkwatch.search.registry", lambda: {"leaksites": Fake()})
    wl = Watchlist(
        settings=Settings(db_path=str(tmp_path / "db.sqlite3"), sources=["leaksites"], delay_seconds=0),
        targets=[Target(name="Someone")], path=tmp_path / "w.yaml",
    )
    result = investigate(wl, "widgets.example", use_tor=False)
    assert result.term_type == "domain"
    assert seen["terms"] == [("widgets.example", "domain", "search:widgets.example")]
    assert len(result.findings) == 1  # only the document that matched
    found = result.findings[0]
    assert isinstance(found, Finding)
    assert found.source == "leaksite" and "financial" in found.signals
    assert result.documents == 2 and result.stats["leaksites"]["note"] == "2 posts"
    assert result.as_dict()["findings"][0]["url"] == "http://gang.onion/x"
    # nothing was written: the database is still empty
    with Store(wl.settings.db_path) as s:
        assert s.hits() == []


def test_investigate_rejects_empty_and_unknown(tmp_path):
    wl = Watchlist(settings=Settings(db_path=str(tmp_path / "db.sqlite3")),
                   targets=[Target(name="X")], path=tmp_path / "w.yaml")
    with pytest.raises(ValueError, match="nothing to search"):
        investigate(wl, "   ")
    with pytest.raises(ValueError, match="term type"):
        investigate(wl, "x", term_type="nonsense")
    with pytest.raises(ValueError, match="unknown sources"):
        investigate(wl, "x", sources=["nope"])


def test_investigate_survives_a_broken_source(tmp_path, monkeypatch):
    class Boom:
        name = "leaksites"
        description = "fake"

        def unavailable_reason(self, settings):
            return ""

        def discover(self, terms, ctx):
            raise RuntimeError("feed exploded")
            yield  # pragma: no cover

    monkeypatch.setattr("darkwatch.search.registry", lambda: {"leaksites": Boom()})
    wl = Watchlist(settings=Settings(db_path=str(tmp_path / "db.sqlite3"), sources=["leaksites"]),
                   targets=[Target(name="X")], path=tmp_path / "w.yaml")
    result = investigate(wl, "acme.example", use_tor=False)
    assert result.findings == []
    assert any("feed exploded" in e for e in result.errors)


def test_source_stats_dataclass_defaults():
    assert SourceStats().documents == 0
