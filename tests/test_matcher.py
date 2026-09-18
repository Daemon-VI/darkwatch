from darkwatch.config import Term
from darkwatch.matcher import Matcher, severity_from_score, severity_rank, signals_in


def _m(value, type_, target="T"):
    return Matcher([Term(value, type_, target)])


def test_email_exact_and_obfuscated():
    m = _m("jane.doe@example.com", "email")
    text = "contact JANE.DOE@example.com or jane.doe [at] example [dot] com today"
    hits = m.find(text)
    assert len(hits) == 2
    assert all(h.term.type == "email" for h in hits)


def test_email_does_not_match_superstring():
    m = _m("doe@example.com", "email")
    assert m.find("janedoe@example.com") == []
    assert m.find("doe@example.company") == []


def test_phone_with_separators_and_country_code():
    m = _m("+91 98765 43210", "phone")
    assert len(m.find("call 98765-43210")) == 1
    assert len(m.find("call +91 (98765) 43210")) == 1
    assert len(m.find("call 9876543210")) == 1
    assert m.find("call 19876543210x") == []  # digit glued on


def test_domain_matches_subdomains_only():
    m = _m("example.com", "domain")
    assert len(m.find("mail.example.com and example.com")) == 2
    assert m.find("notexample.com") == []
    assert m.find("example.com.evil.net") == []
    assert len(m.find("visit example.com.")) == 1  # sentence-ending dot is fine


def test_name_tolerates_separators_and_case():
    m = _m("Jane Doe", "name")
    assert len(m.find("JANE  DOE, jane_doe, jane-doe")) == 3
    assert len(m.find("Jane, Doe / JANE&DOE / jane'doe")) == 3
    # The separator is optional between parts this long: a leak-site title writes the run-together
    # form, and the pre-filter already passes the document, so dropping it here was a silent miss.
    assert len(m.find("janedoe")) == 1
    # ...but not when gluing could swallow an unrelated word.
    assert _m("Al Ice", "name").find("Alice went home") == []
    assert m.find("Jane. Doe is a separate sentence") == []


def test_window_signals_raise_severity():
    m = _m("jane@example.com", "email")
    plain = m.find("hello jane@example.com bye", source="onion")[0]
    hot = m.find("dump for sale: jane@example.com:password123 btc only", source="onion")[0]
    assert plain.signals == []
    assert "credentials" in hot.signals and "sale" in hot.signals
    assert hot.score > plain.score
    assert hot.severity in ("HIGH", "CRITICAL")


def test_signal_text_overrides_window():
    m = _m("jane@example.com", "email")
    prose = "jane@example.com was in a breach that leaked a dump for sale"
    structured = m.find(prose, source="breach", signal_text="Email addresses, Names")[0]
    assert structured.signals == []  # prose words are ignored when data classes are given
    assert structured.severity == "MEDIUM"  # 2 (email) + 2 (breach)
    pw = m.find(prose, source="breach", signal_text="Email addresses, Passwords, Dates of birth")[0]
    assert pw.signals == ["credentials", "government_id"]
    assert pw.severity == "HIGH"


def test_breach_data_class_names():
    assert signals_in("Email addresses, Passwords, Dates of birth, Physical addresses") == [
        "credentials", "government_id", "dox",
    ]
    assert signals_in("Credit cards, Bank account numbers") == ["financial"]
    assert signals_in("Auth tokens, Security questions and answers") == ["credentials"]
    assert signals_in("Names, Phone numbers, Geographic locations") == []


def test_leaksite_scores():
    company = Matcher([Term("acme.example", "domain", "Acme"), Term("Acme Corp", "name", "Acme")])
    text = "Acme Corp was listed on the leak site of the ransomware group x. Website: acme.example."
    found = {h.term.type: h for h in company.find(text, source="leaksite")}
    # leaksite weight is 4: being posted by a gang is the incident, with or without signal words
    assert found["domain"].severity == "CRITICAL"  # 2 + 4 + sale + access
    assert found["name"].severity == "CRITICAL"  # 1 + 4 + sale + access
    # with no signal words at all, being posted by a gang is still HIGH on its own (1or2 + 4)
    bare = company.find("Acme Corp of acme.example", source="leaksite")
    assert {h.term.type: h.severity for h in bare} == {"domain": "HIGH", "name": "HIGH"}


def test_max_per_term():
    m = _m("x@y.io", "email")
    assert len(m.find(" x@y.io " * 20, max_per_term=3)) == 3


def test_snippet_bounds():
    m = _m("x@y.io", "email")
    text = "a" * 1000 + " x@y.io " + "b" * 1000
    h = m.find(text)[0]
    assert h.snippet.startswith("…") and h.snippet.endswith("…")
    assert "x@y.io" in h.snippet
    assert len(h.snippet) < 400


def test_severity_bands_and_rank():
    assert severity_from_score(1) == "LOW"
    assert severity_from_score(3) == "MEDIUM"
    assert severity_from_score(5) == "HIGH"
    assert severity_from_score(7) == "CRITICAL"
    assert severity_rank("critical") > severity_rank("HIGH") > severity_rank("medium") > severity_rank("LOW")
    assert severity_rank("bogus") == 0


def test_page_title_feeds_signals():
    m = _m("canva.com", "domain")
    listing = "Candypvp.Fr 3,279 2017-10-26 Canva.Com 60,390,129 2023-06-19 Canwatchco.Ca 4,748"
    plain = m.find(listing, source="onion")[0]
    titled = m.find(listing, source="onion", title="Leaks")[0]
    assert plain.signals == [] and plain.severity == "MEDIUM"
    assert titled.signals == ["sale"] and titled.severity == "HIGH"


def test_dated_evidence_scores_lower():
    from datetime import UTC, datetime

    from darkwatch.matcher import evidence_year

    m = _m("jane@example.com", "email")
    this_year = str(datetime.now(UTC).year)
    fresh = m.find("jane@example.com", source="breach", signal_text="Passwords", evidence_date=this_year)[0]
    old = m.find("jane@example.com", source="breach", signal_text="Passwords", evidence_date="2012-06-05")[0]
    undated = m.find("jane@example.com", source="breach", signal_text="Passwords", evidence_date="unknown")[0]
    assert fresh.score == undated.score == old.score + 1
    assert old.signals == ["credentials", "dated"] and old.severity == "MEDIUM"
    assert fresh.severity == "HIGH"
    assert evidence_year("2026-09-10T18:29:37+00:00") == 2026
    assert evidence_year("12345") is None and evidence_year(None) is None


def test_phone_glued_country_code_and_trunk_prefix():
    m = _m("+91 98765 43210", "phone")
    for text in ("+919876543210", "919876543210", "00919876543210", "09876543210",
                 "tel:+919876543210", "user:pass:919876543210", "+91-98765-43210"):
        assert len(m.find(text)) == 1, text
    for text in ("19876543210", "998765432100", "9876543210987"):
        assert m.find(text) == [], text


def test_email_rejects_longer_domain():
    m = _m("jane@yahoo.com", "email")
    assert m.find("jane@yahoo.com.br:pass") == []
    assert len(m.find("mail jane@yahoo.com. thanks")) == 1


def test_domain_pattern_is_linear_on_dotted_runs():
    import time

    m = _m("example.com", "domain")
    start = time.perf_counter()
    assert m.find("a." * 100_000 + "x") == []
    assert time.perf_counter() - start < 1.0


def test_words_accept_any_separator_both_ways():
    assert len(_m("Acme-Corp", "name").find("Acme Corp, ACME_CORP, acme.corp, acmecorp")) == 4
    assert len(_m("Acme Inc", "name").find("Acme, Inc. was listed today")) == 1
    assert len(_m("example_person", "username").find("example person")) == 1


def test_all_occurrences_when_uncapped():
    m = _m("x@y.io", "email")
    assert len(m.find(" x@y.io " * 20, max_per_term=None)) == 20
