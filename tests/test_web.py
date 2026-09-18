"""The dashboard's HTTP layer: the security posture it claims, the API it serves, and jobs.

The security tests are the point of this file. The dashboard serves a person's exposure data
out of an HTTP port on their machine, so "every route needs the token" and "a non-loopback Host
is refused" are properties worth a test that fails loudly, not comments in a docstring.
"""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from darkwatch.config import ALL_SOURCES
from darkwatch.storage import Store
from darkwatch.web.jobs import JobManager
from darkwatch.web.server import TOKEN_HEADER, WebConfig, build_app

TOKEN = "test-token-abc"

WATCHLIST = """\
settings:
  tor_manage: never
  tor_proxy: socks5h://127.0.0.1:1
  sources: [leaksites]
  delay_seconds: 0
  db_path: {db}
  reports_dir: {reports}
  notify:
    desktop: false
targets:
  - name: Acme Corp
    kind: company
    domains: [acme.example]
  - name: Jane Doe
    kind: person
    emails: [jane.doe@mail.example]
    usernames: [janedoe]
"""

ROWS = [
    ("Acme Corp", "acme.example", "domain", "leaksite", "http://gang.onion/acme",
     "lockbit: Acme Corp", "Acme Corp listed, 200GB of invoices", ["sale"], 8, "CRITICAL"),
    ("Jane Doe", "jane.doe@mail.example", "email", "breach", "https://xon/Canva",
     "Breach: Canva", "jane.doe@mail.example is in the Canva breach", ["credentials"], 5, "HIGH"),
    ("Jane Doe", "janedoe", "username", "site", "https://github.com/janedoe",
     "GitHub profile: janedoe", "Username janedoe has a public profile", [], 1, "LOW"),
]


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "db.sqlite3"
    wl = tmp_path / "watchlist.yaml"
    wl.write_text(
        WATCHLIST.format(db=db.as_posix(), reports=(tmp_path / "reports").as_posix()),
        encoding="utf-8",
    )
    with Store(db) as s:
        run = s.start_run(["leaksites"])
        for target, term, ttype, source, url, title, snippet, signals, score, sev in ROWS:
            s.upsert_hit(run_id=run, target=target, term=term, term_type=ttype, source=source,
                         url=url, title=title, snippet=snippet, signals=signals, score=score,
                         severity=sev)
        s.finish_run(run, pages=3, new_hits=3, seen_hits=0, errors=[], info={"seconds": 2.0})
    app = build_app(WebConfig(watchlist=wl, token=TOKEN))
    # base_url sets the Host header: the default "testserver" is (correctly) refused by the guard
    with TestClient(app, base_url="http://127.0.0.1:8787", headers={TOKEN_HEADER: TOKEN}) as c:
        c.watchlist_path = wl
        c.fastapi_app = app
        c.tmp = tmp_path
        yield c


def api_endpoints(app) -> list[tuple[str, str]]:
    """Every (method, path) the app declares under /api, taken from its own schema rather than a
    hand-written list, so a route added later is covered by the sweep without anyone remembering."""
    out = []
    for path, methods in app.openapi()["paths"].items():
        if path.startswith("/api"):
            for method in methods:
                out.append((method, path.replace("{hit_id}", "1").replace("{job_id}", "nope")))
    return out


# --------------------------------------------------------------------------- security
def test_no_api_route_is_reachable_without_the_token(client):
    endpoints = api_endpoints(client.fastapi_app)
    assert len(endpoints) >= 14, "the sweep must actually cover the API"
    for method, path in endpoints:
        r = client.request(method, path, headers={TOKEN_HEADER: ""})
        assert r.status_code == 401, f"{method.upper()} {path} -> {r.status_code}"
        assert r.json()["detail"] == "bad or missing token"
    # and the scan endpoint in particular did not start a scan on the way to refusing
    assert client.get("/api/summary").json()["job"] is None


def test_wrong_token_is_refused_and_a_query_token_works(client):
    assert client.get("/api/summary", headers={TOKEN_HEADER: TOKEN + "x"}).status_code == 401
    # the browser gets the token in the URL once, before it can send headers
    assert client.get("/api/summary", params={"t": TOKEN}, headers={TOKEN_HEADER: ""}).status_code == 200


def test_non_loopback_host_header_is_refused(client):
    """Anti-DNS-rebinding: a name that resolves here is still not localhost."""
    r = client.get("/api/summary", headers={"host": "darkwatch.attacker.example"})
    assert r.status_code == 421
    for host in ("localhost:8787", "127.0.0.1:8787", "[::1]:8787"):
        assert client.get("/api/summary", headers={"host": host}).status_code == 200


def test_no_cors_headers_are_ever_sent(client):
    r = client.get("/api/summary", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


def test_triage_is_post_only(client):
    # GET /api/hits/status is matched by /api/hits/{hit_id} and rejected as a bad id, never run
    assert client.get("/api/hits/status").status_code == 422


def test_index_and_health_need_no_token_and_carry_no_data(client):
    page = client.get("/", headers={TOKEN_HEADER: ""})
    assert page.status_code == 200
    assert TOKEN not in page.text  # the page is static; the browser supplies the token
    assert "Darkwatch" in page.text
    health = client.get("/healthz", headers={TOKEN_HEADER: ""})
    assert health.status_code == 200 and health.json()["ok"] is True


# --------------------------------------------------------------------------- reading
def test_summary_describes_the_configuration_and_the_data(client):
    data = client.get("/api/summary").json()
    assert data["total_hits"] == 3 and data["open_hits"] == 3
    assert data["by_severity"] == {"LOW": 1, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 1}
    assert data["by_status"]["new"] == 3
    assert data["last_run"]["new_hits"] == 3
    assert [t["name"] for t in data["targets_configured"]] == ["Acme Corp", "Jane Doe"]
    assert [s["name"] for s in data["sources"]] == list(ALL_SOURCES)
    assert [s["name"] for s in data["sources"] if s["enabled"]] == ["leaksites"]
    assert data["severities"] == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert data["watchlist"] == str(client.watchlist_path)
    assert data["job"] is None


def test_hits_search_filter_and_paginate(client):
    assert client.get("/api/hits").json()["total"] == 3
    assert client.get("/api/hits", params={"q": "invoices"}).json()["total"] == 1
    assert client.get("/api/hits", params={"severity": ["CRITICAL", "HIGH"]}).json()["total"] == 2
    assert client.get("/api/hits", params={"source": "site"}).json()["total"] == 1
    assert client.get("/api/hits", params={"target": "Jane Doe"}).json()["total"] == 2
    assert client.get("/api/hits", params={"term_type": "username"}).json()["total"] == 1
    page = client.get("/api/hits", params={"limit": 1, "offset": 1, "order": "score"}).json()
    assert page["total"] == 3 and len(page["hits"]) == 1
    assert page["hits"][0]["severity"] == "HIGH"  # second by score


def test_hit_detail_carries_the_actions_and_404s_cleanly(client):
    hit_id = client.get("/api/hits").json()["hits"][0]["id"]
    detail = client.get(f"/api/hits/{hit_id}").json()
    assert detail["severity"] == "CRITICAL"
    assert detail["actions"], "a CRITICAL hit must come with something to do about it"
    assert client.get("/api/hits/99999").status_code == 404


def test_facets_timeline_and_runs(client):
    facets = client.get("/api/facets").json()
    assert {f["value"]: f["count"] for f in facets["source"]} == {"leaksite": 1, "breach": 1, "site": 1}
    # severity facets come back worst-first, which is the order the filter bar renders
    assert [f["value"] for f in facets["severity"]] == ["CRITICAL", "HIGH", "LOW"]
    assert client.get("/api/timeline", params={"days": 7}).json()["days"]
    runs = client.get("/api/runs").json()["runs"]
    assert runs[0]["new_hits"] == 3 and runs[0]["sources"] == ["leaksites"]


def test_export_json_and_csv(client):
    rows = client.get("/api/export").json()
    assert len(rows) == 3
    csv_text = client.get("/api/export", params={"fmt": "csv"}).text
    assert csv_text.splitlines()[0].startswith("id,severity,score")
    assert len(csv_text.strip().splitlines()) == 4
    assert "sale" in csv_text  # signals are flattened, not dropped


def test_report_404s_until_one_is_built(client):
    assert client.get("/api/report").status_code == 404
    written = client.post("/api/report/rebuild").json()["written"]
    assert [p.rsplit(".", 1)[1] for p in written] == ["md", "html", "json"]
    assert (client.tmp / "reports" / "latest.html").exists()
    got = client.get("/api/report")
    assert got.status_code == 200 and "Darkwatch" in got.text


# --------------------------------------------------------------------------- triage
def test_status_change_is_applied_and_validated(client):
    ids = [h["id"] for h in client.get("/api/hits").json()["hits"]]
    r = client.post("/api/hits/status", json={"ids": ids[:2], "status": "false_positive", "note": "mine"})
    assert r.json() == {"changed": 2, "status": "false_positive"}
    assert client.get("/api/hits").json()["total"] == 1  # closed hits drop out by default
    assert client.get("/api/hits", params={"include_closed": True}).json()["total"] == 3
    assert client.post("/api/hits/status", json={"ids": ids, "status": "banana"}).status_code == 400
    assert client.post("/api/hits/status", json={"ids": [], "status": "resolved"}).status_code == 400


# --------------------------------------------------------------------------- jobs
def test_search_job_runs_and_streams_to_completion(client, monkeypatch):
    class FakeResult:
        def as_dict(self):
            return {"query": "acme", "findings": [], "sources": ["leaksites"]}

    seen = {}

    def fake_investigate(wl, query, **kw):
        seen["query"] = query
        kw["progress"]("looking")
        return FakeResult()

    monkeypatch.setattr("darkwatch.web.server.investigate", fake_investigate)
    job = client.post("/api/search", json={"query": "acme", "use_tor": False}).json()
    assert job["kind"] == "search" and job["running"] in (True, False)

    for _ in range(100):
        snap = client.get(f"/api/jobs/{job['id']}").json()
        if not snap["running"]:
            break
        time.sleep(0.05)
    assert snap["running"] is False
    assert snap["error"] is None
    assert snap["result"]["query"] == "acme"
    assert seen["query"] == "acme"
    assert any(e["text"] == "looking" for e in snap["events"])

    # the stream replays from the start and ends when the job does, rather than hanging
    with client.stream("GET", f"/api/jobs/{job['id']}/events") as stream:
        payloads = [json.loads(line[6:]) for line in stream.iter_lines() if line.startswith("data: ")]
    assert payloads and payloads[-1]["running"] is False


def test_empty_search_and_missing_job_are_refused(client):
    assert client.post("/api/search", json={"query": "   "}).status_code == 400
    assert client.get("/api/jobs/deadbeef").status_code == 404


def test_only_one_job_at_a_time(client, monkeypatch):
    release = __import__("threading").Event()

    def slow(wl, query, **kw):
        release.wait(5)

        class R:
            def as_dict(self):
                return {}

        return R()

    monkeypatch.setattr("darkwatch.web.server.investigate", slow)
    first = client.post("/api/search", json={"query": "a"})
    assert first.status_code == 200
    second = client.post("/api/search", json={"query": "b"})
    assert second.status_code == 409
    assert "already running" in second.json()["detail"]
    release.set()


def test_job_manager_records_a_failure_instead_of_raising():
    jobs = JobManager()

    def boom(job):
        job.emit("starting")
        raise ValueError("nope")

    job = jobs.start("scan", "x", boom)
    for _ in range(100):
        if not job.running:
            break
        time.sleep(0.02)
    snap = job.snapshot()
    assert snap["running"] is False
    assert snap["error"] == "ValueError: nope"
    assert [e["kind"] for e in snap["events"]] == ["progress", "error"]
    assert jobs.current is None and jobs.last is job


def test_job_snapshot_cursor_only_returns_new_events():
    jobs = JobManager()
    job = jobs.start("search", "x", lambda j: (j.emit("one"), j.emit("two"), {})[-1])
    for _ in range(100):
        if not job.running:
            break
        time.sleep(0.02)
    first = job.snapshot(since=0)
    assert [e["text"] for e in first["events"]] == ["one", "two", "done"]
    assert job.snapshot(since=first["cursor"])["events"] == []
