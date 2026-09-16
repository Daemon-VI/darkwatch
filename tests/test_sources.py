import json

import requests

from darkwatch.config import Settings, Target, Term
from darkwatch.matcher import Matcher
from darkwatch.scanner import RunResult, scan_documents
from darkwatch.sources import Document, SourceContext, SourceStats, registry, terms_present
from darkwatch.sources.ahmia import (
    AhmiaSource,
    parse_ahmia_results,
    parse_search_form,
    plan_fetches,
)
from darkwatch.sources.hibp import HibpSource
from darkwatch.sources.leaksites import (
    LeakSiteSource,
    evidence_url,
    merge_records,
    normalise_ransomlook,
    normalise_ransomware_live,
    to_documents,
)
from darkwatch.sources.xposedornot import XposedOrNotSource, parse_analytics
from darkwatch.storage import Store

ONION_A = "http://abcdefghijklmnop.onion/leaks"
ONION_V3 = "http://" + "a" * 56 + ".onion/"

AHMIA_HTML = f"""
<html><body><form id="searchForm" action="/search/"><input type="hidden" name="9aff83" value="010d72"></form><ol>
<li class="result">
  <h4><a href="/search/redirect?search_term=acme&redirect_url={ONION_A}">Acme leaks</a></h4>
  <p>acme.example employee database dump, 40k rows, btc</p>
  <cite>abcdefghijklmnop.onion/leaks</cite> <span class="lastSeen" data-timestamp="Sept. 1, 2026">1 week</span>
</li>
<li class="result"><h4><a href="/search/redirect?search_term=acme&redirect_url={ONION_A}">dup</a></h4></li>
<li class="result"><h4><a href="{ONION_V3}">Unrelated forum</a></h4><p>cooking</p></li>
</ol></body></html>
"""


def ctx_for(settings=None, clear=None, tor=None, tor_ok=False):
    return SourceContext(
        settings=settings or Settings(delay_seconds=0), clear=clear or requests.Session(),
        tor=tor, tor_ok=tor_ok, stats=SourceStats(),
    )


class FakeResponse:
    def __init__(self, status=200, body="", headers=None, json_body=None):
        self.status_code = status
        self.ok = 200 <= status < 400
        self._body = body if json_body is None else json.dumps(json_body)
        self.text = self._body
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}
        self.encoding = "utf-8"
        self.content = self._body.encode()

    def json(self):
        return json.loads(self._body)

    def raise_for_status(self):
        if not self.ok:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size=1):
        yield self.content

    raw = None

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeSession:
    """Routes by URL prefix; each route is a list of responses consumed in order (last one repeats)."""

    def __init__(self, routes):
        self.routes = {k: list(v) if isinstance(v, list) else [v] for k, v in routes.items()}
        self.calls = []

    def get(self, url, params=None, **kw):
        self.calls.append((url, params))
        for prefix, queue in self.routes.items():
            if url.startswith(prefix):
                resp = queue.pop(0) if len(queue) > 1 else queue[0]
                if isinstance(resp, Exception):
                    raise resp
                return resp
        return FakeResponse(404, "missing")


# --------------------------------------------------------------------------- shared
def test_registry_order_and_protocol():
    reg = registry()
    assert list(reg) == ["leaksites", "xposedornot", "hibp", "ahmia", "seeds"]
    for src in reg.values():
        assert src.description
        assert isinstance(src.unavailable_reason(Settings()), str)
    assert reg["seeds"].unavailable_reason(Settings()) == "no seeds configured"
    assert "DARKWATCH_HIBP_KEY" in reg["hibp"].unavailable_reason(Settings())


def test_terms_present_prefilter():
    terms = [Term("Acme Corp", "name", "A"), Term("+91 98765 43210", "phone", "J"), Term("x@y.io", "email", "J")]
    assert [t.value for t in terms_present("ACME-corp breach", terms)] == ["Acme Corp"]
    assert [t.type for t in terms_present("call 98765.43210", terms)] == ["phone"]
    assert [t.type for t in terms_present("X [at] y [dot] io", terms)] == ["email"]  # agrees with the matcher
    assert [t.type for t in terms_present("look at y.io", terms)] == []
    assert terms_present("", terms) == []


def test_onion_budget_is_shared_and_counted():
    ctx = ctx_for(Settings(max_onion_fetches=2))
    assert ctx.take_onion_budget() and ctx.take_onion_budget()
    assert not ctx.take_onion_budget()
    assert ctx.stats.onion_fetches == 2


# --------------------------------------------------------------------------- ahmia
def test_parse_ahmia_results_and_token():
    res = parse_ahmia_results(AHMIA_HTML)
    assert [r["url"] for r in res] == [ONION_A, ONION_V3]  # duplicate collapsed, rank kept
    assert res[0]["title"] == "Acme leaks" and "database dump" in res[0]["desc"]
    assert res[0]["last_seen"] == "Sept. 1, 2026"
    assert parse_search_form(AHMIA_HTML) == {"9aff83": "010d72"}
    assert parse_search_form("<html></html>") == {}


def test_parse_ahmia_fallback_anchor_scan():
    res = parse_ahmia_results('<a href="/search/redirect?redirect_url=http://abcdefghijklmnop.onion/x">t</a>')
    assert res and res[0]["url"].endswith(".onion/x")


def test_plan_fetches_listing_matches_first_then_top_n():
    results = parse_ahmia_results(AHMIA_HTML)
    terms = [Term("acme.example", "domain", "Acme")]
    assert plan_fetches(results, terms, top=0) == [(results[0], True)]
    assert plan_fetches(results, terms, top=5) == [(results[0], True), (results[1], False)]
    assert plan_fetches(results, [Term("nothing", "name", "x")], top=1) == [(results[0], False)]


def test_ahmia_discover_without_tor_yields_only_matching_listings():
    home = FakeResponse(body=AHMIA_HTML)
    clear = FakeSession({"https://ahmia.fi/search/": FakeResponse(body=AHMIA_HTML), "https://ahmia.fi/": home})
    ctx = ctx_for(clear=clear)
    docs = list(AhmiaSource().discover([Term("acme.example", "domain", "Acme")], ctx))
    assert [(d.source, d.url) for d in docs] == [("ahmia-index", ONION_A)]
    assert clear.calls[1][1] == {"q": "acme.example", "9aff83": "010d72"}  # token sent with the query
    assert "Tor off" in ctx.stats.note


def test_ahmia_discover_refreshes_token_once():
    landing = FakeResponse(body='<form id="searchForm"><input type="hidden" name="k" value="v1"></form>')
    clear = FakeSession({
        "https://ahmia.fi/search/": [landing, FakeResponse(body=AHMIA_HTML)],
        "https://ahmia.fi/": [landing, FakeResponse(body=AHMIA_HTML)],
    })
    docs = list(AhmiaSource().discover([Term("acme.example", "domain", "Acme")], ctx_for(clear=clear)))
    assert len(docs) == 1
    assert [c[0] for c in clear.calls] == [
        "https://ahmia.fi/", "https://ahmia.fi/search/", "https://ahmia.fi/", "https://ahmia.fi/search/",
    ]
    assert clear.calls[3][1]["9aff83"] == "010d72"


AHMIA_ONION_BASE = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/"


def test_ahmia_discover_with_tor_prefers_page_over_listing():
    clear = FakeSession({"https://ahmia.fi/": requests.ConnectionError("must not be used")})
    page_with_term = FakeResponse(body="<title>Acme dump</title>acme.example rows for sale, password lists")
    page_without = FakeResponse(body="<title>Forum</title>nothing relevant")
    tor = FakeSession({AHMIA_ONION_BASE: FakeResponse(body=AHMIA_HTML), ONION_A: page_without,
                       ONION_V3: page_with_term})
    ctx = ctx_for(Settings(delay_seconds=0, tor_workers=2), clear=clear, tor=tor, tor_ok=True)
    docs = list(AhmiaSource().discover([Term("acme.example", "domain", "Acme")], ctx))
    assert clear.calls == []  # the search itself went over Tor, to the onion service
    assert tor.calls[0][0] == AHMIA_ONION_BASE and "via onion service" in ctx.stats.note
    kinds = [(d.source, d.url) for d in docs]
    # A: page fetched but no longer contains the term -> page doc + listing doc as evidence
    # V3: top-N fetch, page contains the term -> page doc only
    assert kinds == [("onion", ONION_A), ("ahmia-index", ONION_A), ("onion", ONION_V3)]
    assert ctx.stats.onion_fetches == 2 and ctx.stats.onion_ok == 2
    assert docs[2].title == "Acme dump"


def test_ahmia_search_failure_is_an_error_not_a_crash():
    clear = FakeSession({"https://ahmia.fi/": requests.ConnectionError("down")})
    ctx = ctx_for(clear=clear)
    assert list(AhmiaSource().discover([Term("x", "name", "X")], ctx)) == []
    assert ctx.errors and "ahmia search failed" in ctx.errors[0]


# --------------------------------------------------------------------------- leak sites
RL_RECORD = {
    "post_title": "Acme Corp", "group_name": "lockbit5", "discovered": "2026-09-01T10:00:00+00:00",
    "published": "2026-08-31T00:00:00+00:00", "website": "acme.example", "country": "IN",
    "activity": "Manufacturing", "description": "We have 200GB of Acme data", "post_url": ONION_A,
    "extrainfos": "{}",
}
LOOK_RECORD = {"post_title": "ACME corp", "group_name": "LockBit5", "discovered": "2026-09-01 11:00",
               "description": "same post", "link": "/x", "magnet": None}
OTHER = {"post_title": "Ransomware Victim Ltd", "group_name": "akira", "discovered": "2026-01-01",
         "description": "unrelated ransomware leak", "post_url": "", "website": ""}


def test_leaksite_normalise_merge_and_documents():
    rl = [normalise_ransomware_live(RL_RECORD), normalise_ransomware_live(OTHER)]
    look = [normalise_ransomlook(LOOK_RECORD), normalise_ransomlook({"post_title": None})]
    merged = merge_records(rl, look)
    assert len(merged) == 2
    assert merged[0]["also_seen_by"] == {"RansomLook"}
    assert normalise_ransomlook(LOOK_RECORD)["post_url"] == "https://www.ransomlook.io/group/LockBit5"
    terms = Target(name="Acme Corp", kind="company", domains=["acme.example"], keywords=["ransomware"]).terms()
    docs = list(to_documents(merged, terms))
    # "ransomware" matches OTHER's own description, but never every record via our template text
    assert [d.meta["group"] for d in docs] == ["lockbit5", "akira"]
    acme = docs[0]
    assert acme.url == ONION_A and acme.source == "leaksite"
    assert docs[1].url == "leaksite:akira/Ransomware%20Victim%20Ltd"  # no claim URL: per-post id
    look_only = normalise_ransomlook(dict(LOOK_RECORD, post_title="Other Co"))
    assert evidence_url(look_only) == "leaksite:LockBit5/Other%20Co"
    assert "Website: acme.example" in acme.text and "200GB" in acme.text
    assert acme.meta["also_seen_by"] == ["RansomLook"]
    hits = Matcher(Target(name="Acme Corp", kind="company", domains=["acme.example"]).terms()).find(
        acme.text, source=acme.source
    )
    assert {h.severity for h in hits} == {"CRITICAL", "HIGH"}


def test_leaksite_discover_uses_cache(tmp_path, http_server, monkeypatch):
    http_server.add("/victims.json", body=[RL_RECORD, OTHER], headers={"ETag": '"v1"'})
    http_server.add("/api/last/30", body=[LOOK_RECORD])
    monkeypatch.setattr("darkwatch.sources.leaksites.RANSOMWARE_LIVE_URL", http_server.base + "/victims.json")
    monkeypatch.setattr("darkwatch.sources.leaksites.RANSOMLOOK_URL", http_server.base + "/api/last/{days}")
    settings = Settings(delay_seconds=0, cache_dir=str(tmp_path / "cache"))
    terms = [Term("acme.example", "domain", "Acme")]
    ctx = ctx_for(settings)
    docs = list(LeakSiteSource().discover(terms, ctx))
    assert len(docs) == 1 and ctx.errors == []
    assert ctx.stats.note == "2 unique posts checked" and ctx.stats.requests == 2
    ctx2 = ctx_for(settings)
    assert len(list(LeakSiteSource().discover(terms, ctx2))) == 1
    assert len(http_server.requests) == 2  # second run served from the fresh cache
    assert ctx2.stats.requests == 0


def test_leaksite_bad_feed_is_reported(tmp_path, http_server, monkeypatch):
    http_server.add("/victims.json", body="not json", headers={"Content-Type": "application/json"})
    http_server.add("/api/last/30", status=500, body="boom")
    monkeypatch.setattr("darkwatch.sources.leaksites.RANSOMWARE_LIVE_URL", http_server.base + "/victims.json")
    monkeypatch.setattr("darkwatch.sources.leaksites.RANSOMLOOK_URL", http_server.base + "/api/last/{days}")
    ctx = ctx_for(Settings(delay_seconds=0, cache_dir=str(tmp_path / "c")))
    assert list(LeakSiteSource().discover([Term("x", "name", "X")], ctx)) == []
    assert any("not JSON" in e for e in ctx.errors)
    assert any("unavailable" in e for e in ctx.errors)


# --------------------------------------------------------------------------- xposedornot / hibp
XON = {
    "ExposedBreaches": {"breaches_details": [
        {"breach": "Canva", "domain": "canva.com", "xposed_date": "2019", "xposed_records": 137272116,
         "xposed_data": "Email addresses;Names;Passwords;Usernames", "password_risk": "hardtocrack",
         "details": "In May 2019 the graphic design tool Canva suffered a data breach"},
        {"breach": "Tiny", "xposed_data": "Email addresses", "details": ""},
    ]},
    "ExposedPastes": None,
    "PastesSummary": {"cnt": 2, "domain": "pastebin.com", "tmpstmp": "2020"},
}


def test_xposedornot_parse():
    docs = parse_analytics("jane@x.io", XON)
    assert [d.source for d in docs] == ["breach", "breach", "paste"]
    canva = docs[0]
    assert "137,272,116 records" in canva.text and canva.signal_text == "Email addresses, Names, Passwords, Usernames"
    hits = Matcher([Term("jane@x.io", "email", "J")]).find(canva.text, source="breach", signal_text=canva.signal_text)
    assert hits[0].signals == ["credentials"] and hits[0].severity == "HIGH"
    assert "2 public paste(s)" in docs[2].text
    listed = parse_analytics("jane@x.io", {"ExposedPastes": [{"id": "p1", "source": "Pastebin", "date": "2021"}],
                                            "PastesSummary": {"cnt": 1}})
    assert [d.title for d in listed] == ["Paste on Pastebin"]
    assert parse_analytics("a@b.c", {"ExposedBreaches": None, "ExposedPastes": None, "PastesSummary": None}) == []


def test_xposedornot_discover_statuses():
    clear = FakeSession({
        "https://api.xposedornot.com/v1/breach-analytics?email=a%40x.io": FakeResponse(json_body=XON),
        "https://api.xposedornot.com/v1/breach-analytics?email=b%40x.io": FakeResponse(json_body={"Error": "Not found"}),
        "https://api.xposedornot.com/v1/breach-analytics?email=c%40x.io": FakeResponse(429, "slow down"),
    })
    terms = [Term(e, "email", "T") for e in ("a@x.io", "b@x.io", "c@x.io")]
    ctx = ctx_for(clear=clear)
    src = XposedOrNotSource()
    src_throttle = ctx.throttle
    ctx.throttle = lambda key, seconds=None: src_throttle(key, 0)
    docs = list(src.discover(terms, ctx))
    assert len(docs) == 3
    assert any("rate limited" in e for e in ctx.errors)


def test_hibp_domain_lookup_without_key_and_account_with_key():
    breach = {"Name": "Acme", "Title": "Acme", "Domain": "acme.example", "BreachDate": "2024-01-01",
              "PwnCount": 1000, "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True}
    clear = FakeSession({
        "https://haveibeenpwned.com/api/v3/breaches?domain=acme.example": FakeResponse(json_body=[breach]),
        "https://haveibeenpwned.com/api/v3/breachedaccount/": FakeResponse(json_body=[breach]),
        "https://haveibeenpwned.com/api/v3/pasteaccount/": FakeResponse(404, ""),
    })
    terms = [Term("acme.example", "domain", "A"), Term("ceo@acme.example", "email", "A")]
    ctx = ctx_for(clear=clear)
    ctx.throttle = lambda key, seconds=None: None
    docs = list(HibpSource().discover(terms, ctx))
    assert [d.title for d in docs] == ["HIBP: Acme was breached"]
    assert "per-email lookups skipped" in ctx.stats.note
    keyed = ctx_for(Settings(delay_seconds=0, hibp_api_key="k"), clear=clear)
    keyed.throttle = lambda key, seconds=None: None
    docs = list(HibpSource().discover(terms, keyed))
    assert [d.source for d in docs] == ["breach", "breach"]
    assert "ceo@acme.example is in the Acme breach" in docs[1].text


def test_hibp_bad_key_stops():
    clear = FakeSession({"https://haveibeenpwned.com/api/v3/breachedaccount/": FakeResponse(401, "")})
    ctx = ctx_for(Settings(delay_seconds=0, hibp_api_key="bad"), clear=clear)
    ctx.throttle = lambda key, seconds=None: None
    assert list(HibpSource().discover([Term("a@b.c", "email", "A"), Term("d@e.f", "email", "A")], ctx)) == []
    assert ctx.errors == ["hibp: API key rejected (401)"]
    assert len(clear.calls) == 1


# --------------------------------------------------------------------------- scan loop
def test_scan_documents_end_to_end(tmp_path):
    terms = Target(name="Acme", kind="company", domains=["acme.com"], emails=["ceo@acme.com"]).terms()
    docs = [
        Document(url="http://x.onion/1", title="dump", text="ceo@acme.com:hunter2 in combo list for sale", source="onion"),
        Document(url="http://x.onion/2", title="about", text="nothing to see here", source="onion"),
        Document(url="http://y.onion/p", title="paste", text="mail.acme.com admin panel rdp access", source="seed"),
        Document(url="hibp", title="b", text="ceo@acme.com is in a breach", source="breach", signal_text="Names"),
    ]
    store = Store(tmp_path / "db.sqlite3")
    run_id = store.start_run(["fake"])
    result = RunResult(run_id=run_id, sources=["fake"], tor_ok=False, tor_info={})
    stats = SourceStats()
    scan_documents(docs, Matcher(terms), store, run_id, result, stats)
    assert result.pages == 4 and stats.documents == 4
    # doc1: email + domain (inside the email) + name (inside the domain); doc3: domain + name; doc4: 3 again
    assert len(result.new_hits) == 8 and stats.new_hits == 8
    by = {(h.url, h.term_type): h for h in result.new_hits}
    assert by[("http://x.onion/1", "email")].severity == "HIGH"  # 2 + onion 2 + credentials + sale
    assert by[("hibp", "email")].signals == [] and by[("hibp", "email")].severity == "MEDIUM"
    result2 = RunResult(run_id=run_id, sources=["fake"], tor_ok=False, tor_info={})
    scan_documents(docs, Matcher(terms), store, run_id, result2)
    assert result2.new_hits == [] and result2.seen_hits == 8
    store.close()


def test_decode_body_charsets():
    from darkwatch.fetch import decode_body

    utf8 = "curl · example — ok".encode()
    assert decode_body(utf8, "text/html") == "curl · example — ok"  # no charset: UTF-8, not Latin-1
    assert decode_body("café".encode("cp1252"), "text/html") == "café"  # not UTF-8: cp1252
    assert decode_body("café".encode("latin-1"), "text/html; charset=ISO-8859-1") == "café"
    meta = b'<html><head><meta charset="windows-1251"></head>' + "Привет".encode("cp1251")
    assert "Привет" in decode_body(meta, "text/html")
    assert decode_body(b"x", "text/html; charset=bogus-9") == "x"


def test_one_hit_per_term_per_document(tmp_path):
    terms = [Term("example.com", "keyword", "E")]
    text = " ".join(["example.com"] * 4 + ["password dump for sale example.com"])
    docs = [Document(url="http://p.onion/", title="Guide", text=text, source="onion")]
    with Store(tmp_path / "db.sqlite3") as store:
        run_id = store.start_run(["x"])
        result = RunResult(run_id=run_id, sources=["x"], tor_ok=False, tor_info={})
        scan_documents(docs, Matcher(terms), store, run_id, result)
    assert len(result.new_hits) == 1
    assert result.new_hits[0].signals == ["credentials", "sale"]  # the strongest occurrence was kept


def test_leaksite_post_signals_read_the_whole_post():
    record = dict(RL_RECORD, description=("x " * 200) + "staff passport scans and all bank accounts")
    docs = list(to_documents([normalise_ransomware_live(record)], [Term("Acme Corp", "name", "A")]))
    assert docs[0].evidence_date.startswith("2026-08-31")
    hit = Matcher([Term("Acme Corp", "name", "A")]).find(
        docs[0].text, source="leaksite", signal_text=docs[0].signal_text, evidence_date=docs[0].evidence_date
    )[0]
    assert hit.signals == ["financial", "government_id", "sale", "access"]
    assert hit.severity == "CRITICAL"


def test_ahmia_page_fetched_for_one_query_suppresses_listing_in_another():
    clear = FakeSession({})
    tor = FakeSession({AHMIA_ONION_BASE: FakeResponse(body=AHMIA_HTML),
                       ONION_A: FakeResponse(body="acme.example leaked"), ONION_V3: FakeResponse(body="x")})
    ctx = ctx_for(Settings(delay_seconds=0, tor_workers=1), clear=clear, tor=tor, tor_ok=True)
    terms = [Term("zzz-unlisted", "keyword", "Z"), Term("acme.example", "domain", "Acme")]
    docs = list(AhmiaSource().discover(terms, ctx))
    # query 1 fetches both pages via top-N; query 2 matches A's listing, but A's page already has the term
    assert [(d.source, d.url) for d in docs] == [("onion", ONION_A), ("onion", ONION_V3)]
    assert ctx.stats.onion_fetches == 2


def test_scan_documents_reports_escalations(tmp_path):
    terms = [Term("ceo@acme.com", "email", "Acme")]
    weak = [Document(url="http://f.onion/t", title="forum", text="contact ceo@acme.com", source="onion")]
    strong = [Document(url="http://f.onion/t", title="forum",
                       text="selling ceo@acme.com password list for btc", source="onion")]
    with Store(tmp_path / "db.sqlite3") as store:
        run_id = store.start_run(["x"])
        first = RunResult(run_id=run_id, sources=["x"], tor_ok=False, tor_info={})
        scan_documents(weak, Matcher(terms), store, run_id, first)
        second = RunResult(run_id=run_id, sources=["x"], tor_ok=False, tor_info={})
        scan_documents(strong, Matcher(terms), store, run_id, second)
    assert len(first.new_hits) == 1 and first.alertable == first.new_hits
    assert second.new_hits == [] and len(second.escalated_hits) == 1
    assert second.escalated_hits[0].severity == "HIGH"  # MEDIUM -> HIGH (sale + credentials) and second.alertable == second.escalated_hits
    assert second.run_info()["escalated_hits"] == 1


def test_best_match_is_found_beyond_the_fifth_occurrence(tmp_path):
    terms = [Term("janedoe", "username", "J")]
    text = "posted by janedoe. " * 6 + "janedoe password: hunter2 combolist for sale btc"
    docs = [Document(url="http://forum.onion/t", title="thread", text=text, source="onion")]
    with Store(tmp_path / "db.sqlite3") as store:
        run_id = store.start_run(["x"])
        result = RunResult(run_id=run_id, sources=["x"], tor_ok=False, tor_info={})
        scan_documents(docs, Matcher(terms), store, run_id, result)
    assert result.new_hits[0].signals == ["credentials", "sale"]
    assert result.new_hits[0].severity == "HIGH"


def test_require_tor_false_still_fetches_when_the_exit_check_fails(tmp_path, monkeypatch):
    import contextlib

    from darkwatch import scanner
    from darkwatch.config import Watchlist

    seen = {}

    class Probe:
        name = "ahmia"
        description = "probe"

        def unavailable_reason(self, settings):
            return ""

        def discover(self, terms, ctx):
            seen["tor_ok"] = ctx.tor_ok
            return iter(())

    monkeypatch.setattr(scanner, "registry", lambda: {"ahmia": Probe()})
    monkeypatch.setattr(scanner, "_maybe_tor", lambda s, needed, progress: contextlib.nullcontext(
        {"managed": False, "bootstrap_seconds": None, "error": ""}))
    monkeypatch.setattr(scanner, "check_tor", lambda session, timeout=30: {"IsTor": False, "IP": "?", "error": "Timeout"})
    for require, expected in ((True, False), (False, True)):
        wl = Watchlist(settings=Settings(db_path=str(tmp_path / f"{require}.sqlite3"), require_tor=require,
                                         sources=["ahmia"]),
                       targets=[Target(name="X")], path=tmp_path / "w.yaml")
        result = scanner.run_scan(wl)
        assert seen["tor_ok"] is expected
        assert any("Tor check failed (Timeout)" in e for e in result.errors)


def test_ahmia_routes():
    from darkwatch.sources.ahmia import search_routes

    clear, tor = object(), object()
    auto_tor = ctx_for(Settings(delay_seconds=0), clear=clear, tor=tor, tor_ok=True)
    assert [r[0] for r in search_routes(auto_tor)] == ["onion service", "ahmia.fi over Tor"]
    assert search_routes(ctx_for(Settings(delay_seconds=0), clear=clear)) == [("clearnet", clear)]
    assert search_routes(ctx_for(Settings(delay_seconds=0, ahmia_route="tor"), clear=clear)) == []
    forced = ctx_for(Settings(delay_seconds=0, ahmia_route="clearnet"), clear=clear, tor=tor, tor_ok=True)
    assert search_routes(forced) == [("clearnet", clear)]


def test_ahmia_falls_back_to_ahmia_fi_over_tor_never_clearnet():
    clear = FakeSession({"https://ahmia.fi/": requests.ConnectionError("must not be used")})
    tor = FakeSession({
        AHMIA_ONION_BASE: requests.ConnectionError("onion service down"),
        "https://ahmia.fi/": FakeResponse(body=AHMIA_HTML),
        ONION_A: FakeResponse(body="acme.example"), ONION_V3: FakeResponse(body="x"),
    })
    ctx = ctx_for(Settings(delay_seconds=0, onion_fetch_top=0), clear=clear, tor=tor, tor_ok=True)
    docs = list(AhmiaSource().discover([Term("acme.example", "domain", "Acme")], ctx))
    assert [d.source for d in docs] == ["onion"]
    assert clear.calls == [] and "via ahmia.fi over Tor" in ctx.stats.note
    down = FakeSession({AHMIA_ONION_BASE: requests.ConnectionError("x"),
                        "https://ahmia.fi/": requests.ConnectionError("y")})
    ctx2 = ctx_for(Settings(delay_seconds=0), clear=clear, tor=down, tor_ok=True)
    assert list(AhmiaSource().discover([Term("acme.example", "domain", "Acme")], ctx2)) == []
    assert clear.calls == [] and "every route" in ctx2.errors[0]


def test_ahmia_listing_kept_when_page_only_loosely_contains_term():
    tor = FakeSession({AHMIA_ONION_BASE: FakeResponse(body=AHMIA_HTML),
                       ONION_A: FakeResponse(body="see acme.examples.net"), ONION_V3: FakeResponse(body="x")})
    ctx = ctx_for(Settings(delay_seconds=0), clear=FakeSession({}), tor=tor, tor_ok=True)
    docs = list(AhmiaSource().discover([Term("acme.example", "domain", "Acme")], ctx))
    assert ("ahmia-index", ONION_A) in [(d.source, d.url) for d in docs]


def test_ahmia_hostile_page_does_not_end_the_source(monkeypatch):
    from darkwatch.sources import ahmia as ahmia_mod

    def boom(*a, **k):
        raise UnicodeError("undefined encoding")

    monkeypatch.setattr(ahmia_mod, "fetch_text", boom)
    tor = FakeSession({AHMIA_ONION_BASE: FakeResponse(body=AHMIA_HTML)})
    ctx = ctx_for(Settings(delay_seconds=0), clear=FakeSession({}), tor=tor, tor_ok=True)
    terms = [Term("acme.example", "domain", "Acme"), Term("other.example", "domain", "Other")]
    docs = list(AhmiaSource().discover(terms, ctx))
    assert [(d.source, d.url) for d in docs] == [("ahmia-index", ONION_A)]
    assert len([c for c in tor.calls if c[0].endswith("search/")]) == 2  # the second term was searched


def test_ahmia_reports_listings_beyond_the_cap():
    clear = FakeSession({"https://ahmia.fi/": FakeResponse(body=AHMIA_HTML)})
    ctx = ctx_for(Settings(delay_seconds=0, max_results_per_term=1), clear=clear)
    list(AhmiaSource().discover([Term("acme.example", "domain", "Acme")], ctx))
    assert "1 beyond max_results_per_term skipped" in ctx.stats.note


def test_seeds_route_every_hop(http_server):
    from darkwatch.sources.seeds import SeedSource

    http_server.add("/start", 302, b"", {"Location": "http://abcdefghijklmnop.onion/leak"})
    http_server.add("/page", 200, "<title>t</title><a href='/start'>x</a> acme.example")
    s = Settings(delay_seconds=0, seeds=[http_server.base + "/page"])
    ctx = ctx_for(s, clear=requests.Session())  # no Tor
    docs = list(SeedSource().discover([Term("acme.example", "domain", "A")], ctx))
    assert [d.url for d in docs] == [http_server.base + "/page"]
    assert any("redirected somewhere unsafe" in e for e in ctx.errors)  # /start -> onion refused
    assert [r["path"] for r in http_server.requests] == ["/page", "/start"]


def test_empty_onion_results_page_links_to_itself_not_to_results():
    base = AHMIA_ONION_BASE
    html = (
        '<html><body><form id="searchForm" action="/search/"><input type="hidden" name="k" value="v"></form>'
        f'<a href="{base}search/?q=%2B91+98765+43210&k=v&d=1">Last day</a>'
        f'<a href="{base}search/?q=%2B91+98765+43210&k=v&d=all">Any time</a>'
        '<a href="https://ahmia.fi/about/">About</a>'
        '<p>No results for +91 98765 43210</p></body></html>'
    )
    assert parse_ahmia_results(html) == []
    tor = FakeSession({base: FakeResponse(body=html)})
    ctx = ctx_for(Settings(delay_seconds=0), clear=FakeSession({}), tor=tor, tor_ok=True)
    assert list(AhmiaSource().discover([Term("+91 98765 43210", "phone", "R")], ctx)) == []
    assert ctx.stats.onion_fetches == 0
