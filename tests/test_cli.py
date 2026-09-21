"""End-to-end CLI behaviour with the network replaced by a fake source."""

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from darkwatch import cli
from darkwatch.sources import Document

runner = CliRunner()


class FakeLeakSource:
    name = "leaksites"
    description = "fake"

    def unavailable_reason(self, settings):
        return ""

    def discover(self, terms, ctx):
        ctx.stats.note = "fake feed"
        yield Document(
            url="http://abcdefghijklmnop.onion/acme",
            title="lockbit leak site: Acme Corp",
            text="Acme Corp was listed on the leak site of the ransomware group lockbit. Website: acme.example.",
            source="leaksite",
        )
        yield Document(url="http://x.onion/", title="noise", text="nothing here", source="leaksite")


class CrashingSource(FakeLeakSource):
    name = "xposedornot"

    def discover(self, terms, ctx):
        raise RuntimeError("feed exploded")
        yield  # pragma: no cover


@pytest.fixture(autouse=True)
def fake_registry(monkeypatch):
    monkeypatch.setattr(
        "darkwatch.scanner.registry",
        lambda: {"leaksites": FakeLeakSource(), "xposedornot": CrashingSource()},
    )


def invoke(*args):
    result = runner.invoke(cli.app, [str(a) for a in args], catch_exceptions=False, env={"COLUMNS": "250"})
    return result


def test_version_and_init(tmp_path):
    from darkwatch import __version__

    assert f"darkwatch {__version__}" in invoke("version").output
    target = tmp_path / "w.yaml"
    r = invoke("init", target)
    assert r.exit_code == 0 and target.exists() and (tmp_path / ".env.example").exists()
    assert invoke("init", target).exit_code == 1  # never overwrites
    assert "DARKWATCH_NTFY_TOPIC" in (tmp_path / ".env.example").read_text()


def test_bad_watchlist_exits_2(tmp_path):
    p = tmp_path / "w.yaml"
    p.write_text("settings:\n  nope: 1\ntargets:\n  - name: X\n")
    r = invoke("run", "-w", p)
    assert r.exit_code == 2 and "unknown settings" in r.output
    assert invoke("hits", "-w", tmp_path / "missing.yaml").exit_code == 2


def test_run_report_triage_cycle(watchlist_file):
    w = watchlist_file
    r = invoke("run", "-w", w, "--sources", "leaksites,xposedornot", "--no-notify")
    assert r.exit_code == 0, r.output
    assert "2 document(s), 2 new hit(s)" in r.output
    assert "source xposedornot crashed: RuntimeError: feed exploded" in r.output
    reports = w.parent / "reports"
    assert (reports / "latest.html").exists() and (reports / "latest.md").exists()
    md = (reports / "latest.md").read_text(encoding="utf-8")
    assert "fake feed" in md and md.count("[CRITICAL]") == 2  # leaksite weight 4 + sale + access
    data = json.loads((reports / "latest.json").read_text(encoding="utf-8"))
    ids = [h["id"] for h in data["hits"]]
    assert len(ids) == 2 and data["run"]["source_stats"]["leaksites"]["new_hits"] == 2

    again = invoke("run", "-w", w, "--sources", "leaksites", "--no-notify")
    assert "0 new hit(s), 0 escalated, 2 already known" in again.output

    assert "2 hit(s)" in invoke("hits", "-w", w).output
    crit = invoke("hits", "-w", w, "--min-severity", "CRITICAL", "--snippets").output
    assert "2 hit(s)" in crit and "Acme Corp was listed" in crit
    show = invoke("show", ids[0], "-w", w)
    assert "Recommended actions" in show.output and "CERT-In" in show.output
    assert invoke("show", 999, "-w", w).exit_code == 1

    assert "1 hit(s) marked acknowledged" in invoke("ack", ids[0], "-w", w, "--note", "IR engaged").output
    assert "1 hit(s) marked false_positive" in invoke("false-positive", ids[1], "-w", w).output
    open_hits = invoke("hits", "-w", w)
    assert "1 hit(s)" in open_hits.output and "acknowledged" in open_hits.output
    assert "2 hit(s)" in invoke("hits", "-w", w, "--all").output
    assert "1 hit(s)" in invoke("hits", "-w", w, "--status", "false_positive").output
    assert invoke("hits", "-w", w, "--status", "bogus").exit_code == 2
    r = invoke("resolve", ids[0], 12345, "-w", w)
    assert "1 hit(s) marked resolved" in r.output and "1 id(s) not found" in r.output
    assert "No hits match." in invoke("hits", "-w", w).output
    invoke("reopen", ids[0], "-w", w)
    assert "1 hit(s)" in invoke("hits", "-w", w).output

    rep = invoke("report", "-w", w, "--formats", "md")
    assert rep.exit_code == 0 and "latest" not in rep.output
    assert invoke("report", "-w", w, "--formats", "pdf").exit_code == 2
    runs = invoke("runs", "-w", w)
    assert runs.exit_code == 0 and "leaksites" in runs.output


def test_run_lock_blocks_second_run(watchlist_file):
    from darkwatch.schedule import RunLock

    path = watchlist_file.parent / "data" / "run.lock"
    holder = RunLock(path)
    assert holder.acquire() is None
    try:
        r = invoke("run", "-w", watchlist_file, "--sources", "leaksites", "--no-notify")
        assert r.exit_code == 3 and f"pid {os.getpid()}" in r.output
    finally:
        holder.release()
    # the lock file stays behind, but without the OS lock it does not block
    assert invoke("run", "-w", watchlist_file, "--sources", "leaksites", "--no-notify").exit_code == 0


def test_run_notifies_with_report_link(watchlist_file, monkeypatch):
    calls = []
    monkeypatch.setattr("darkwatch.notify.notify", lambda n, hits, report_path=None, tag="": calls.append(
        (len(hits), report_path, tag)) or {"desktop": True, "ntfy": None, "webhook": None, "email": None})
    r = invoke("run", "-w", watchlist_file, "--sources", "leaksites")
    assert "alert desktop: sent" in r.output
    assert calls[0][0] == 2 and calls[0][1].endswith("latest.html") and calls[0][2].startswith("run")


def test_log_file_mode_writes_everything_to_file(watchlist_file, tmp_path):
    log = tmp_path / "logs" / "dw.log"
    r = invoke("--log-file", log, "run", "-w", watchlist_file, "--sources", "leaksites", "--no-notify")
    assert r.exit_code == 0
    text = log.read_text(encoding="utf-8")
    assert "new hit(s)" in text and "source leaksites: start" in text
    bad = tmp_path / "bad.yaml"
    bad.write_text("settings: [unclosed\n", encoding="utf-8")
    r = invoke("--log-file", log, "run", "-w", bad)
    assert r.exit_code == 2
    assert "is not valid YAML" in log.read_text(encoding="utf-8")
    # restore module-level consoles for the other tests
    cli._setup_output(False, None)
    cli.console = cli.Console()
    cli.err = cli.Console(stderr=True)


def test_scan_text_and_save(watchlist_file, tmp_path):
    dump = tmp_path / "dump.txt"
    dump.write_text("jane.doe@mail.example:Winter2024! combo\nunrelated line\n", encoding="utf-8")
    r = invoke("scan-text", dump, "-w", watchlist_file, "--save")
    # the email, and the name "Jane Doe" inside its local part
    assert "2 match(es)" in r.output and "signals=credentials" in r.output
    assert "combo unrelated line" in r.output  # snippet printed on one line
    hits = invoke("hits", "-w", watchlist_file, "--all")
    assert "jane.doe@mail.example" in hits.output and "file" in hits.output


def test_hostile_titles_do_not_break_output(watchlist_file, monkeypatch):
    class Hostile(FakeLeakSource):
        def discover(self, terms, ctx):
            yield Document(url="http://h.onion/[/b/]", title="Acme Corp dump [/pol/ leaks] [/]",
                           text="Acme Corp [/] leak site ransomware", source="leaksite")

    monkeypatch.setattr("darkwatch.scanner.registry", lambda: {"leaksites": Hostile()})
    r = invoke("run", "-w", watchlist_file, "--sources", "leaksites", "--no-notify")
    assert r.exit_code == 0, r.output
    assert "[/pol/ leaks]" in r.output
    data = json.loads((watchlist_file.parent / "reports" / "latest.json").read_text(encoding="utf-8"))
    hid = data["hits"][0]["id"]
    assert invoke("hits", "-w", watchlist_file, "--snippets").exit_code == 0
    assert "[/pol/ leaks]" in invoke("show", hid, "-w", watchlist_file).output
    assert invoke("hits", "-w", watchlist_file, "--min-severity", "critcal").exit_code == 2


def test_reports_leave_out_targets_removed_from_the_watchlist(watchlist_file):
    invoke("run", "-w", watchlist_file, "--sources", "leaksites", "--no-notify")
    acme = "  - name: Acme Corp\n    kind: company\n    domains: [acme.example]\n    aliases: [AcmeCo]\n"
    text = watchlist_file.read_text()
    assert acme in text
    watchlist_file.write_text(text.replace(acme, ""))
    invoke("report", "-w", watchlist_file, "--formats", "md")
    md = (watchlist_file.parent / "reports" / "latest.md").read_text(encoding="utf-8")
    assert "2 open hit(s) belong to targets that are no longer in the watchlist" in md
    assert "## Acme Corp" not in md


def test_sources_listing(watchlist_file):
    r = invoke("sources", "-w", watchlist_file)
    assert r.exit_code == 0
    for name in ("leaksites", "xposedornot", "hibp", "ahmia", "seeds"):
        assert name in r.output


def test_open_without_report(watchlist_file):
    assert invoke("open", "-w", watchlist_file).exit_code == 1


def test_notify_test_reports_channels(watchlist_file, monkeypatch):
    monkeypatch.setattr("darkwatch.notify.send_desktop", lambda *a, **k: True)
    text = watchlist_file.read_text().replace("desktop: false", "desktop: true")
    watchlist_file.write_text(text)
    r = invoke("notify-test", "-w", watchlist_file)
    assert r.exit_code == 0 and "desktop: sent" in r.output and "ntfy: not configured" in r.output
    monkeypatch.setattr("darkwatch.notify.send_desktop", lambda *a, **k: False)
    assert invoke("notify-test", "-w", watchlist_file).exit_code == 1


def test_check_tor_unavailable(watchlist_file):
    r = invoke("check-tor", "-w", watchlist_file)
    assert r.exit_code == 2 and "Tor unavailable" in r.output


def test_schedule_commands_use_schtasks(monkeypatch, watchlist_file):
    calls = []

    class Done:
        returncode = 0
        stdout = "SUCCESS"
        stderr = ""

    def fake_schtasks(*args):
        calls.append(args)
        if args[0] == "/Query":
            Done.stdout = "TaskName: \\Darkwatch daily scan\nNext Run Time: 17-09-2026 09:00:00\nStatus: Ready\n"
        return Done()

    monkeypatch.setattr("darkwatch.schedule._schtasks", fake_schtasks)
    r = invoke("schedule", "install", "-w", watchlist_file, "--at", "06:45")
    assert r.exit_code == 0 and "daily at 06:45" in r.output
    assert calls[0][:3] == ("/Create", "/TN", "Darkwatch daily scan") and calls[0][3] == "/XML"
    assert not Path(calls[0][4]).exists()  # temp XML cleaned up
    assert invoke("schedule", "install", "-w", watchlist_file, "--at", "99:00").exit_code == 2
    st = invoke("schedule", "status")
    assert "Next Run Time" in st.output and "Ready" in st.output
    assert invoke("schedule", "run-now").exit_code == 0
    assert invoke("schedule", "remove").exit_code == 0
    assert [c[0] for c in calls] == ["/Create", "/Query", "/Run", "/Delete"]


def test_search_finds_stored_hits_by_keyword(watchlist_file):
    w = watchlist_file
    assert invoke("run", "-w", w, "--sources", "leaksites", "--no-notify").exit_code == 0

    found = invoke("search", "lockbit", "-w", w).output
    assert "hit(s) in" in found and "ms" in found  # the timing is part of the answer
    assert "No hits match" in invoke("search", "nonsense-token", "-w", w).output
    # every token must match, across any column
    assert "No hits match" in invoke("search", "lockbit nonsense-token", "-w", w).output
    assert "hit(s) in" in invoke("search", '"Acme Corp"', "-w", w).output

    assert "hit(s) in" in invoke("search", "-w", w, "--severity", "CRITICAL").output
    assert "No hits match" in invoke("search", "-w", w, "--severity", "LOW").output
    assert "hit(s) in" in invoke("search", "-w", w, "--source", "leaksite").output
    assert "hit(s) in" in invoke("search", "-w", w, "--target", "Acme Corp").output
    assert invoke("search", "-w", w, "--order", "sideways").exit_code == 2

    facets = invoke("search", "-w", w, "--facets").output
    assert "severity:" in facets and "CRITICAL" in facets and "source:" in facets


def test_search_on_an_empty_database_says_so(watchlist_file):
    assert "No hits stored yet." in invoke("search", "-w", watchlist_file).output


def test_investigate_reports_findings_without_storing_them(watchlist_file, monkeypatch):
    from darkwatch.search import Finding, Investigation

    captured = {}

    def fake(wl, query, *, term_type="", sources=None, use_tor=True, progress=lambda m: None):
        captured.update(query=query, term_type=term_type, sources=sources, use_tor=use_tor)
        progress("looking")
        return Investigation(
            query=query, term_type=term_type or "email", sources=["leaksites"], documents=4,
            seconds=1.2,
            findings=[Finding("x@y.example", "email", "leaksite", "http://a.onion/x", "Leak",
                              "x@y.example for sale", ["sale"], 7, "CRITICAL")],
        )

    monkeypatch.setattr("darkwatch.search.investigate", fake)
    r = invoke("investigate", "x@y.example", "-w", watchlist_file, "--no-tor")
    assert r.exit_code == 0, r.output
    assert "read as email" in r.output and "4 document(s)" in r.output
    assert "not stored" in r.output and "CRITICAL" in r.output
    assert captured["use_tor"] is False

    # and nothing reached the database
    from darkwatch.config import load_watchlist
    from darkwatch.storage import Store

    with Store(load_watchlist(watchlist_file).settings.db_path) as store:
        assert store.hits() == []


def test_investigate_says_nothing_found_plainly(watchlist_file, monkeypatch):
    from darkwatch.search import Investigation

    monkeypatch.setattr(
        "darkwatch.search.investigate",
        lambda wl, query, **kw: Investigation(query=query, term_type="keyword", sources=["leaksites"]),
    )
    out = invoke("investigate", "acme", "-w", watchlist_file).output
    assert "Nothing found." in out and "not a silent failure" in out


def test_investigate_validates_its_options(watchlist_file):
    assert invoke("investigate", "x", "-w", watchlist_file, "--type", "bogus").exit_code == 2
    r = invoke("investigate", "x", "-w", watchlist_file, "--sources", "leaksites,nope")
    assert r.exit_code == 2 and "unknown sources" in r.output


def _json_from(output: str):
    """The JSON blob a --json command prints, tolerating any leading log lines."""
    s = output.strip()
    starts = [p for p in (s.find("["), s.find("{")) if p != -1]
    assert starts, f"no JSON in output: {output!r}"
    return json.loads(s[min(starts):])


def test_hits_json_is_machine_readable(watchlist_file):
    w = watchlist_file
    assert invoke("run", "-w", w, "--sources", "leaksites", "--no-notify").exit_code == 0
    data = _json_from(invoke("hits", "-w", w, "--json").output)
    assert isinstance(data, list) and data
    assert {"id", "severity", "source", "term", "url", "snippet", "signals"} <= set(data[0])
    # every field the VS Code extension groups and shows is present and typed
    assert data[0]["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert isinstance(data[0]["signals"], list)
    # an empty database is an empty array, not an error or a message
    assert _json_from(invoke("hits", "-w", w, "--status", "resolved", "--json").output) == []


def test_search_json_carries_page_and_facets(watchlist_file):
    w = watchlist_file
    assert invoke("run", "-w", w, "--sources", "leaksites", "--no-notify").exit_code == 0
    page = _json_from(invoke("search", "acme", "-w", w, "--json").output)
    assert page["total"] >= 1 and page["query"] == "acme"
    assert isinstance(page["took_ms"], (int, float))
    assert {"severity", "source", "status", "target", "term_type"} <= set(page["facets"])
    # a miss is a clean empty page, still valid JSON
    miss = _json_from(invoke("search", "no-such-token-xyz", "-w", w, "--json").output)
    assert miss["total"] == 0 and miss["hits"] == []
