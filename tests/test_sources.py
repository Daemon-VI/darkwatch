import json

import requests

from darkwatch.config import ALL_SOURCES, Settings, Target, Term
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
    assert list(reg) == [
        "leaksites", "recentattacks", "stealers", "leakcheck", "xposedornot", "hibp",
        "sites", "telegram", "ahmia", "seeds",
    ]
    assert list(reg) == list(ALL_SOURCES)  # the registry and the config list cannot drift apart
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
    # RansomLook's `link` is a path on ransomlook.io, so it resolves to the post itself
    assert normalise_ransomlook(LOOK_RECORD)["post_url"] == "https://www.ransomlook.io/x"
    assert normalise_ransomlook({"post_title": "A", "group_name": "g"})["post_url"] ==         "https://www.ransomlook.io/group/g"
    terms = Target(name="Acme Corp", kind="company", domains=["acme.example"], keywords=["ransomware"]).terms()
    docs = list(to_documents(merged, terms))
    # "ransomware" matches OTHER's own description, but never every record via our template text
    assert [d.meta["group"] for d in docs] == ["lockbit5", "akira"]
    acme = docs[0]
    assert acme.url == ONION_A and acme.source == "leaksite"
    assert docs[1].url == "leaksite:akira/Ransomware%20Victim%20Ltd"  # no claim URL: per-post id
    look_only = normalise_ransomlook(dict(LOOK_RECORD, post_title="Other Co"))
    assert evidence_url(look_only) == "https://www.ransomlook.io/x"  # the post's own path
    no_link = normalise_ransomlook({"post_title": "Other Co", "group_name": "LockBit5"})
    assert evidence_url(no_link) == "leaksite:LockBit5/Other%20Co"  # only a group page: synthesise
    assert "Website: acme.example" in acme.text and "200GB" in acme.text
    assert acme.meta["also_seen_by"] == ["RansomLook"]
    hits = Matcher(Target(name="Acme Corp", kind="company", domains=["acme.example"]).terms()).find(
        acme.text, source=acme.source, signal_text=acme.signal_text
    )
    # scored on the tracker's own words, not on our framing sentence: no signal group fires here,
    # so both are HIGH from the leaksite weight alone rather than CRITICAL from our own wording
    assert {h.term.type: h.severity for h in hits} == {"domain": "HIGH", "name": "HIGH"}


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
    # the post's own text carries these; "leak site"/"ransomware" is our wording and is excluded
    assert hit.signals == ["financial", "government_id"]
    assert hit.severity == "CRITICAL"  # 1 + 4 + 2


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


# --------------------------------------------------------------------------- sites (person profiles)
def test_site_classify():
    from darkwatch.sources.sites import Site, classify

    plain = Site("X", "https://x/{username}")
    assert classify(200, "welcome", plain) == "present"
    assert classify(404, "not found", plain) == "absent"
    assert classify(403, "", plain) == "unknown"  # blocked: do not guess
    assert classify(500, "", plain) == "unknown"
    hn = Site("HN", "u", missing_status=200, absent_markers=("No such user.",))
    assert classify(200, "No such user.", hn) == "absent"
    assert classify(200, "created: 2016 karma: 9", hn) == "present"


def test_build_sites_adds_extras():
    from darkwatch.config import Settings
    from darkwatch.sources.sites import build_sites

    only_extra = build_sites(Settings(person_site_builtins=False, person_sites=["https://s/{username}"]))
    assert [x.name for x in only_extra] == ["s"]
    assert build_sites(Settings(person_site_builtins=False)) == []
    assert "GitHub" in [x.name for x in build_sites(Settings())]


def test_sites_discover_finds_profiles_and_coincident_identifiers(http_server):
    from darkwatch.config import Settings, Target
    from darkwatch.sources.sites import SiteSource

    # profile for "jdoe" exists and its page shows the person's real name; "ghost" is 404
    http_server.add("/u/jdoe", 200, "<title>jdoe</title> jdoe - developer, real name Jane Doe, London")
    http_server.add("/u/ghost", 404, "not found")
    http_server.add("/hn/jdoe", 404, "not found")  # user sites detect by status only
    s = Settings(delay_seconds=0, person_site_builtins=False,
                 person_sites=[http_server.base + "/u/{username}", http_server.base + "/hn/{username}"])
    terms = Target(name="Jane Doe", usernames=["jdoe", "ghost"]).terms()
    ctx = ctx_for(s)
    docs = list(SiteSource().discover(terms, ctx))
    assert [d.url for d in docs] == [http_server.base + "/u/jdoe"]  # only the real profile, once
    assert docs[0].source == "site" and docs[0].signal_text == ""
    # the matcher then reads that profile: the username AND the person's real name are found on it
    from darkwatch.matcher import Matcher
    from darkwatch.storage import Store

    with Store(":memory:") as store:
        run = store.start_run(["x"])
        result = RunResult(run_id=run, sources=["x"], tor_ok=False, tor_info={})
        scan_documents(docs, Matcher(terms), store, run, result)
    kinds = sorted((h.term, h.term_type, h.severity, tuple(h.signals)) for h in result.new_hits)
    assert ("Jane Doe", "name", "LOW", ()) in kinds  # real name pulled off the profile page
    assert ("jdoe", "username", "LOW", ()) in kinds
    assert all(h.signals == [] for h in result.new_hits)  # profile chrome never manufactures signals
    assert "1/4 profile checks matched" in ctx.stats.note


def test_sites_ignores_page_chrome_signals(http_server):
    from darkwatch.config import Settings, Target
    from darkwatch.matcher import Matcher
    from darkwatch.sources.sites import SiteSource

    # a profile whose boilerplate contains signal words must still score LOW with no signals
    http_server.add("/u/bob", 200, "bob. Reload to refresh your session. password dump for sale btc")
    s = Settings(delay_seconds=0, person_site_builtins=False, person_sites=[http_server.base + "/u/{username}"])
    terms = Target(name="Bob", usernames=["bob"]).terms()
    docs = list(SiteSource().discover(terms, ctx_for(s)))
    hits = Matcher(terms).find(docs[0].text, source=docs[0].source, signal_text=docs[0].signal_text)
    # no real signal group from the page's own chrome; a bare repeat of the handle is marked
    # uncorroborated rather than scored
    assert all(h.severity == "LOW" for h in hits)
    assert all(set(h.signals) <= {"uncorroborated"} for h in hits)


def test_sites_no_usernames_is_a_noop():
    from darkwatch.config import Settings, Target
    from darkwatch.sources.sites import SiteSource

    ctx = ctx_for(Settings(delay_seconds=0))
    assert list(SiteSource().discover(Target(name="Acme", domains=["acme.com"]).terms(), ctx)) == []


# --------------------------------------------------------------------------- stealers (Hudson Rock)
# Shapes taken from live responses on 2026-09-18: the API returns list values as Python-style
# string literals, and masks the stolen values themselves.
HR_INFECTED = {
    "message": "This email address is associated with a computer that was infected by an info-stealer",
    "stealers": [
        {
            "total_corporate_services": 2,
            "total_user_services": 17,
            "date_compromised": "2024-03-11T00:00:00.000Z",
            "computer_name": "DESKTOP-9F2K",
            "operating_system": "Windows 10 Pro",
            "malware_path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\setup.exe",
            "antiviruses": "['Windows Defender']",
            "ip": "106.192.**.***",
            "top_passwords": "['P********3', 'h*****1']",
            "top_logins": "['jdoe@mail.example']",
        }
    ],
}
HR_CLEAN = {"message": "This email address is not associated with ...", "stealers": []}


def test_stealer_document_reports_the_machine_and_never_the_secret():
    from darkwatch.sources.stealers import parse

    docs = parse("jdoe@mail.example", "email", HR_INFECTED)
    assert len(docs) == 1
    doc = docs[0]
    assert doc.source == "stealer"
    assert doc.evidence_date.startswith("2024-03-11")
    assert doc.meta["corporate_services"] == 2
    assert "DESKTOP-9F2K" in doc.title and "DESKTOP-9F2K" in doc.text
    # the masked forms are kept verbatim: they identify the machine without being a credential
    assert "P********3" in doc.text and "106.192.**.***" in doc.text
    # the list-literal strings the API sends are unpacked, not printed raw
    assert "['P********3'" not in doc.text
    assert "Windows Defender" in doc.text
    # an infostealer takes credentials by definition; corporate services also mean network access
    assert "credentials" in doc.signal_text and "initial access" in doc.signal_text


def test_stealer_document_without_corporate_services_claims_no_network_access():
    from darkwatch.sources.stealers import parse

    record = {**HR_INFECTED["stealers"][0], "total_corporate_services": 0}
    doc = parse("jdoe@mail.example", "email", {"stealers": [record]})[0]
    assert "credentials" in doc.signal_text
    assert "initial access" not in doc.signal_text
    assert "corporate" not in doc.text


def test_stealer_hit_from_an_infection_is_critical():
    from darkwatch.sources.stealers import parse

    doc = parse("jdoe@mail.example", "email", HR_INFECTED)[0]
    hit = Matcher([Term("jdoe@mail.example", "email", "J")]).find(
        doc.text, source=doc.source, signal_text=doc.signal_text, evidence_date=doc.evidence_date
    )[0]
    # base 2 (email) + weight 4 (stealer) + credentials + access: a live infection is the most
    # actionable thing Darkwatch can find about a person, and it is scored that way
    assert hit.severity == "CRITICAL"


def test_stealers_clean_answer_yields_nothing_and_is_counted():
    from darkwatch.sources.stealers import BASE, StealerSource

    session = FakeSession({BASE: FakeResponse(json_body=HR_CLEAN)})
    ctx = ctx_for(Settings(delay_seconds=0), clear=session)
    terms = [Term("jdoe@mail.example", "email", "J"), Term("jdoe", "username", "J")]
    assert list(StealerSource().discover(terms, ctx)) == []
    assert ctx.stats.note == "0/2 identifier(s) found in infostealer logs"
    assert ctx.errors == []
    assert [c[0].split("/")[-1].split("?")[0] for c in session.calls] == [
        "search-by-email", "search-by-username"
    ]


def test_stealers_stops_on_rate_limit_and_survives_junk():
    from darkwatch.sources.stealers import BASE, StealerSource

    ctx = ctx_for(Settings(delay_seconds=0), clear=FakeSession({BASE: FakeResponse(429, "slow down")}))
    terms = [Term(f"u{i}", "username", "J") for i in range(4)]
    assert list(StealerSource().discover(terms, ctx)) == []
    assert any("rate limited" in e for e in ctx.errors)
    assert ctx.stats.requests == 1  # it stopped rather than burning the remaining three

    ctx = ctx_for(Settings(delay_seconds=0), clear=FakeSession({BASE: FakeResponse(200, "<html>nope")}))
    assert list(StealerSource().discover([Term("jdoe", "username", "J")], ctx)) == []
    assert any("not JSON" in e for e in ctx.errors)


# --------------------------------------------------------------------------- leakcheck
LC_FOUND = {
    "success": True,
    "found": 3,
    "fields": ["email", "password", "dob", "ssn", "first_name"],
    "sources": [
        {"name": "Canva.com", "date": "2019-05"},
        {"name": "Collection1", "date": "2019-01"},
        {"name": "Older.example", "date": "2012-07"},
    ],
}


def test_leakcheck_names_the_data_classes_that_leaked():
    from darkwatch.sources.leakcheck import parse

    docs = parse("jdoe@mail.example", LC_FOUND)
    assert [d.title for d in docs] == ["Breach: Canva.com", "Breach: Collection1", "Breach: Older.example"]
    assert [d.evidence_date for d in docs] == ["2019-05", "2019-01", "2012-07"]  # newest first
    # the field names become the words the signal groups recognise, so severity reflects what leaked
    assert "social security" in docs[0].signal_text and "date of birth" in docs[0].signal_text
    assert all(d.source == "breach" for d in docs)
    assert len({d.url for d in docs}) == 3  # one stable identity per breach, not per query


def test_leakcheck_scores_a_government_id_leak_above_a_plain_one():
    from darkwatch.sources.leakcheck import parse

    m = Matcher([Term("jdoe@mail.example", "email", "J")])
    hot = parse("jdoe@mail.example", LC_FOUND)[0]
    mild = parse("jdoe@mail.example", {**LC_FOUND, "fields": ["email"]})[0]
    hot_hit = m.find(hot.text, source=hot.source, signal_text=hot.signal_text)[0]
    mild_hit = m.find(mild.text, source=mild.source, signal_text=mild.signal_text)[0]
    assert set(hot_hit.signals) >= {"credentials", "government_id"}
    assert hot_hit.score > mild_hit.score


def test_leakcheck_not_found_is_a_clean_negative():
    from darkwatch.sources.leakcheck import API, LeakCheckSource

    body = {"success": False, "error": "Not found"}
    session = FakeSession({API.split("?")[0]: FakeResponse(json_body=body)})
    ctx = ctx_for(Settings(delay_seconds=0), clear=session)
    terms = [Term("jdoe@mail.example", "email", "J"), Term("acme.com", "domain", "A")]
    assert list(LeakCheckSource().discover(terms, ctx)) == []
    # only the email was looked up: LeakCheck's public tier answers for emails and usernames
    assert len(session.calls) == 1
    assert ctx.stats.note == "0/1 identifier(s) found in breach data"


def test_leakcheck_caps_breaches_per_identifier():
    from darkwatch.sources.leakcheck import MAX_SOURCES_PER_TERM, parse

    many = {**LC_FOUND, "sources": [{"name": f"b{i}", "date": "2020-01"} for i in range(60)]}
    assert len(parse("jdoe@mail.example", many)) == MAX_SOURCES_PER_TERM


# --------------------------------------------------------------------------- xposedornot by domain
XON_DOMAIN = {
    "status": "success",
    "exposedBreaches": [
        {
            "breachID": "Adobe",
            "breachedDate": "2013-10-04T00:00:00.000Z",
            "exposedData": ["Email", "Password", "Password Hints"],
            "exposedRecords": 152445165,
            "passwordRisk": "easytocrack",
        }
    ],
}


def test_xposedornot_domain_breach_becomes_evidence():
    from darkwatch.sources.xposedornot import parse_domain

    docs = parse_domain("acme.example", XON_DOMAIN)
    assert len(docs) == 1
    doc = docs[0]
    assert doc.meta == {"provider": "XposedOrNot", "breach": "Adobe", "domain": "acme.example"}
    assert "152,445,165 records" in doc.text
    assert "easytocrack" in doc.text
    assert doc.evidence_date.startswith("2013-10-04")
    assert "Password" in doc.signal_text
    assert parse_domain("acme.example", {"status": "error"}) == []


def test_default_sites_are_well_formed_and_distinct():
    from darkwatch.sources.sites import DEFAULT_SITES, SiteSource

    assert len(DEFAULT_SITES) >= 24
    assert len({s.name for s in DEFAULT_SITES}) == len(DEFAULT_SITES)
    assert len({s.url for s in DEFAULT_SITES}) == len(DEFAULT_SITES)
    for site in DEFAULT_SITES:
        assert "{username}" in site.url
        assert site.url.startswith("https://")
        # a soft-404 site is only usable if it declares the marker that proves absence
        if site.missing_status == 200:
            assert site.absent_markers, f"{site.name} needs an absent marker"
        assert "%20" in site.profile_url("a b"), f"{site.name} must escape the handle"
    # the description is derived, so it can never name a site the source does not check
    assert str(len(DEFAULT_SITES)) in SiteSource().description


def test_sites_are_checked_in_parallel(http_server):
    """Two dozen sites per handle is only affordable because the checks overlap."""
    import threading

    from darkwatch.config import Settings, Target
    from darkwatch.sources.sites import SiteSource

    for i in range(8):
        http_server.add(f"/s{i}/jdoe", 200, "jdoe")
    templates = [http_server.base + f"/s{i}/{{username}}" for i in range(8)]
    s = Settings(delay_seconds=0, person_site_builtins=False, person_sites=templates, site_workers=8)
    ctx = ctx_for(s)

    threads: set[str] = set()
    original = SiteSource._check

    def record(self, site, username, ctx):
        threads.add(threading.current_thread().name)
        return original(self, site, username, ctx)

    SiteSource._check = record
    try:
        docs = list(SiteSource().discover(Target(name="J", usernames=["jdoe"]).terms(), ctx))
    finally:
        SiteSource._check = original

    assert len(docs) == 8
    assert ctx.stats.requests == 8  # every check is still counted
    assert len(threads) > 1, "the checks ran one after another"
    assert all(t.startswith("site") for t in threads)
    assert "8/8 profile checks matched across 8 site(s)" in ctx.stats.note


def test_sites_with_nothing_to_check_is_a_noop():
    from darkwatch.config import Settings, Target
    from darkwatch.sources.sites import SiteSource

    # no sites configured and eight workers: no pool larger than the work, no crash
    ctx = ctx_for(Settings(delay_seconds=0, person_site_builtins=False, person_sites=[], site_workers=8))
    assert list(SiteSource().discover(Target(name="J", usernames=["jdoe"]).terms(), ctx)) == []

# --------------------------------------------------------------------------- recentattacks
RA_FEED = [
    {"victim": "Acme Corp", "domain": "acme.example", "country": "IN", "date": "2026-08-01",
     "claim_gang": "lockbit", "summary": "Acme Corp disclosed unauthorised access exposing employee records.",
     "link": "https://www.ransomware.live/id/abc", "has_infostealer_info": True},
    {"victim": "", "domain": "", "summary": "no victim, should be skipped"},
]


def test_recentattacks_builds_one_document_per_incident():
    from darkwatch.sources.recentattacks import to_document

    doc = to_document(RA_FEED[0])
    assert doc is not None
    assert doc.source == "attack"
    assert doc.evidence_date == "2026-08-01"
    assert doc.url == "https://www.ransomware.live/id/abc"
    assert "Acme Corp" in doc.text and "lockbit" in doc.text
    # signals come from the disclosure, not from Darkwatch's own sentence
    assert "acme.example" in doc.signal_text and "employee records" in doc.signal_text
    assert doc.meta["has_infostealer"] is True
    assert to_document(RA_FEED[1]) is None


def test_recentattacks_matches_a_watched_company():
    from darkwatch.sources.recentattacks import to_document

    doc = to_document(RA_FEED[0])
    hit = Matcher([Term("acme.example", "domain", "A")]).find(
        doc.text, source=doc.source, signal_text=doc.signal_text, evidence_date=doc.evidence_date
    )[0]
    assert hit.severity in ("HIGH", "CRITICAL")  # base 2 + weight 3 + signals


def test_recentattacks_survives_a_broken_feed():
    from darkwatch.sources.recentattacks import FEED, RecentAttacksSource

    ctx = ctx_for(Settings(delay_seconds=0), clear=FakeSession({FEED: FakeResponse(500, "boom")}))
    assert list(RecentAttacksSource().discover([Term("acme.example", "domain", "A")], ctx)) == []
    assert any("feed download failed" in e for e in ctx.errors)


def test_recentattacks_emits_and_counts():
    from darkwatch.sources.recentattacks import FEED, RecentAttacksSource

    ctx = ctx_for(Settings(delay_seconds=0), clear=FakeSession({FEED: FakeResponse(json_body=RA_FEED)}))
    docs = list(RecentAttacksSource().discover([Term("acme.example", "domain", "A")], ctx))
    assert [d.source for d in docs] == ["attack"]  # the empty one is dropped
    assert "1 recent incident(s) checked" in ctx.stats.note


# --------------------------------------------------------------------------- telegram
TG_PAGE = """
<div class="tgme_widget_message" data-post="leakchan/42">
  <div class="tgme_widget_message_text">Fresh dump: jane.doe@example.com:hunter2 and 500 more lines</div>
</div>
<div class="tgme_widget_message" data-post="leakchan/43">
  <div class="tgme_widget_message_text">unrelated crypto advertisement</div>
</div>
"""


def test_telegram_parses_and_filters_to_the_term():
    from darkwatch.sources.telegram import messages_with_term, parse_messages

    assert len(parse_messages(TG_PAGE)) == 2
    hits = messages_with_term(TG_PAGE, Term("jane.doe@example.com", "email", "J"))
    assert len(hits) == 1
    url, text = hits[0]
    assert url == "https://t.me/leakchan/42"
    assert "jane.doe@example.com" in text
    # a term not on the page returns nothing (Telegram's fuzzy search is re-checked locally)
    assert messages_with_term(TG_PAGE, Term("someone.else@example.com", "email", "J")) == []


def test_telegram_channels_list_ships_and_is_ordered():
    from darkwatch.sources.telegram import load_channels

    channels = load_channels()
    assert len(channels) > 100
    kinds = [c["kind"] for c in channels]
    # infostealer channels (which carry credentials) are checked first under a cap
    assert kinds.index("infostealer") < kinds.index("threat-actor")
    assert all(c["handle"] and " " not in c["handle"] for c in channels)


def test_telegram_source_searches_live_channels_only(monkeypatch):
    from darkwatch.sources import telegram as tg

    monkeypatch.setattr(tg, "load_channels", lambda: [
        {"handle": "leakchan", "kind": "infostealer"},
        {"handle": "deadchan", "kind": "threat-actor"},
    ])
    routes = {
        "https://t.me/s/leakchan": FakeResponse(200, TG_PAGE),
        "https://t.me/s/deadchan": FakeResponse(200, "<html>join this channel</html>"),  # no messages
    }
    ctx = ctx_for(Settings(delay_seconds=0, telegram_max_channels=0), clear=FakeSession(routes))
    docs = list(tg.TelegramSource().discover([Term("jane.doe@example.com", "email", "J")], ctx))
    assert len(docs) == 1
    assert docs[0].source == "telegram"
    assert docs[0].meta["channel"] == "leakchan"
    # infostealer channel contributes credential signals; the matcher then scores them
    assert "credentials" in docs[0].signal_text
    assert "1 message(s) across 1 live channel(s) of 2 checked; 1 gone or private" in ctx.stats.note


def test_telegram_respects_the_channel_cap(monkeypatch):
    from darkwatch.sources import telegram as tg

    monkeypatch.setattr(tg, "load_channels", lambda: [
        {"handle": f"c{i}", "kind": "threat-actor"} for i in range(10)
    ])
    calls = []

    class Rec(FakeSession):
        def get(self, url, params=None, **kw):
            calls.append(url)
            return FakeResponse(200, "<html>nothing</html>")

    ctx = ctx_for(Settings(delay_seconds=0, telegram_max_channels=3), clear=Rec({}))
    list(tg.TelegramSource().discover([Term("jane.doe@example.com", "email", "J")], ctx))
    assert len(calls) == 3  # only the first three channels, and each dies after one request


def test_telegram_skips_when_no_query_terms():
    from darkwatch.sources.telegram import TelegramSource

    ctx = ctx_for(Settings(delay_seconds=0))
    # only a phone term, which telegram deliberately does not search
    assert list(TelegramSource().discover([Term("+91 98765 43210", "phone", "J")], ctx)) == []


# --------------------------------------------------------------------------- deep mode
def test_deepen_only_raises_limits_and_enables_every_source():
    from darkwatch.config import ALL_SOURCES
    from darkwatch.scanner import deepen

    base = Settings(onion_fetch_top=80, telegram_max_channels=5)
    d = deepen(base)
    assert d.sources == list(ALL_SOURCES)
    assert d.telegram_max_channels == 0  # 0 means all
    assert d.onion_fetch_top == 80  # already higher than the deep floor of 50: left alone
    assert d.max_onion_fetches == 2000
    assert d.onion_link_depth == 1
    assert Settings().onion_fetch_top == 5  # the original is untouched
