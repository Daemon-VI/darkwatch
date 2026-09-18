"""Recall against realistic dark-web renderings, as a measured regression test.

An audit on 2026-09-18 measured 69% recall (62 of 90) on the corpus below and found that 19 of
the 28 misses were *silent*: the pre-filter said the identifier was present and the matcher then
recorded nothing. Both numbers are now asserted, so neither can drift back unnoticed.

Every case is a way an identifier actually appears in a leak post, a combolist, a paste, a forum
thread or a threat-intel write-up. Cases that must NOT match live in `FALSE_POSITIVES`, because
recall bought with false positives is not worth having.
"""

from __future__ import annotations

import pytest

from darkwatch.config import Term
from darkwatch.fetch import html_to_text
from darkwatch.matcher import Matcher
from darkwatch.sources import terms_present

EMAIL = "jane.doe@example.com"
PHONE = "+91 98765 43210"
DOMAIN = "example.com"
USER = "night_owl"
NAME = "Jane Doe"
KEYWORD = "Acme Corp"

CORPUS: list[tuple[str, str, str]] = [
    # ---- email: how an address shows up in a dump, a paste, a forum post
    ("email", EMAIL, "jane.doe@example.com"),
    ("email", EMAIL, "JANE.DOE@EXAMPLE.COM"),
    ("email", EMAIL, "jane.doe@example.com:Summer2023!"),
    ("email", EMAIL, "line 2601: jane.doe@example.com:hunter2"),
    ("email", EMAIL, '{"email":"jane.doe@example.com","pass":"x"}'),
    ("email", EMAIL, "id,email,pass\n7,jane.doe@example.com,abc"),
    ("email", EMAIL, "contact jane.doe [at] example [dot] com for escrow"),
    ("email", EMAIL, "jane.doe(at)example(dot)com"),
    ("email", EMAIL, "jane.doe@example[.]com"),
    ("email", EMAIL, "mailto:jane.doe@example.com?subject=hi"),
    ("email", EMAIL, "&lt;jane.doe@example.com&gt; leaked"),
    ("email", EMAIL, "jane.doe@exam\u200bple.com"),  # zero-width space
    ("email", EMAIL, "owner: jane.doe@example.com."),
    ("email", EMAIL, "  jane.doe@example.com  "),
    ("email", EMAIL, "<p>Found: <strong>jane.doe</strong>@example.com</p>"),  # via html_to_text
    # ---- phone
    ("phone", PHONE, "+91 98765 43210"),
    ("phone", PHONE, "+919876543210"),
    ("phone", PHONE, "919876543210"),
    ("phone", PHONE, "0091 98765 43210"),
    ("phone", PHONE, "09876543210"),
    ("phone", PHONE, "phone: 9876543210"),
    ("phone", PHONE, "+91-98765-43210"),
    ("phone", PHONE, "+91 (98765) 43210"),
    ("phone", PHONE, "tel:+919876543210"),
    ("phone", PHONE, "mobile 98765.43210"),
    ("phone", PHONE, "whatsapp 98765 43210"),
    ("phone", PHONE, "+91‑98765‑43210"),  # non-breaking hyphens
    ("phone", PHONE, "contact number 9876543210 for otp"),
    ("phone", PHONE, "name,phone\nx,+91 98765 43210"),
    ("phone", PHONE, "call +91 98765 43210 now"),
    # ---- domain
    ("domain", DOMAIN, "example.com"),
    ("domain", DOMAIN, "https://example.com/login"),
    ("domain", DOMAIN, "mail.example.com"),
    ("domain", DOMAIN, "EXAMPLE.COM"),
    ("domain", DOMAIN, "victim: example.com (40k rows)"),
    ("domain", DOMAIN, "example[.]com"),
    ("domain", DOMAIN, "example(.)com"),
    ("domain", DOMAIN, "hxxps://example[.]com/dump"),
    ("domain", DOMAIN, "example [dot] com"),
    ("domain", DOMAIN, "example.com:443"),
    ("domain", DOMAIN, "www.example.com."),
    ("domain", DOMAIN, "exam\u200bple.com"),
    ("domain", DOMAIN, "Website: example.com."),
    ("domain", DOMAIN, "<b>example</b>.com"),
    ("domain", DOMAIN, '"domain":"example.com"'),
    # ---- username
    ("username", USER, "night_owl"),
    ("username", USER, "@night_owl"),
    ("username", USER, "user: night_owl"),
    ("username", USER, "github.com/night_owl"),
    ("username", USER, "NIGHT_OWL"),
    ("username", USER, "night-owl"),
    ("username", USER, "night.owl"),
    ("username", USER, "posted by night_owl on 2026-01-02"),
    ("username", USER, "handle night_owl sells access"),
    ("username", USER, "nick: night_owl"),
    ("username", USER, "account night_owl banned"),
    ("username", USER, "/u/night_owl"),
    ("username", USER, "night_owl:pass123"),
    ("username", USER, "profile night_owl"),
    ("username", USER, "<a>night_owl</a>"),
    # ---- name
    ("name", NAME, "Jane Doe"),
    ("name", NAME, "JANE DOE"),
    ("name", NAME, "jane doe"),
    ("name", NAME, "Jane  Doe"),
    ("name", NAME, "Jane_Doe"),
    ("name", NAME, "Jane-Doe"),
    ("name", NAME, "Jane.Doe"),
    ("name", NAME, "name: Jane Doe, dob 2005"),
    ("name", NAME, "owner Jane Doe (India)"),
    ("name", NAME, "Jane Doe's records"),
    ("name", NAME, "Jane Doe"),  # non-breaking space
    ("name", NAME, "<td>Jane Doe</td>"),
    ("name", NAME, '"full_name":"Jane Doe"'),
    ("name", NAME, "Jane Doe — leaked"),
    ("name", NAME, "director Jane Doe appointed"),
    # ---- keyword / company
    ("keyword", KEYWORD, "Acme Corp"),
    ("keyword", KEYWORD, "ACME CORP"),
    ("keyword", KEYWORD, "Acme-Corp"),
    ("keyword", KEYWORD, "Acme_Corp"),
    ("keyword", KEYWORD, "acme corp data for sale"),
    ("keyword", KEYWORD, "victim: Acme Corp (manufacturing)"),
    ("keyword", KEYWORD, "Acme Corp, India"),
    ("keyword", KEYWORD, "<h2>Acme Corp</h2>"),
    ("keyword", KEYWORD, '"victim":"Acme Corp"'),
    ("keyword", KEYWORD, "Acme Corp"),
    ("keyword", KEYWORD, "[Acme Corp]"),
    ("keyword", KEYWORD, "Acme Corp's files"),
    ("keyword", KEYWORD, "re: Acme Corp breach"),
    ("keyword", KEYWORD, "ACME  CORP  DUMP"),
    ("keyword", KEYWORD, "Acme Corp—200GB"),
]

# Text that must NOT produce a hit: recall is only worth having if it stays specific.
FALSE_POSITIVES: list[tuple[str, str, str]] = [
    ("name", NAME, "Ask Jane. Doe will confirm the totals."),
    ("keyword", KEYWORD, "Contact Acme. Corp filings are public."),
    ("username", USER, "The night. Owl is an editor."),
    ("email", EMAIL, "doe@example.com"),
    ("email", EMAIL, "jane.doe@example.com.br"),
    ("domain", DOMAIN, "notexample.com"),
    ("domain", DOMAIN, "example.com.evil.net"),
    ("phone", PHONE, "19876543210"),
    ("phone", PHONE, "998765432100"),
]


def render(text: str) -> str:
    """HTML cases go through the real extractor, as a fetched page would."""
    return html_to_text(text)[1] if text.lstrip().startswith("<") else text


def _match(kind: str, value: str, text: str) -> bool:
    return bool(Matcher([Term(value, kind, "T")]).find(render(text), source="onion"))


def test_recall_on_realistic_renderings():
    """Full recall, and the docs say so.

    The threshold was 0.96 while the docs claimed 100%, which let a corpus case with a typo in it
    sit undetected: the number in PROJECT_STATE was no longer guarded by anything. A miss here is
    either a real regression or a corpus case that needs fixing; both deserve a failing test.
    """
    misses = [(k, t) for k, v, t in CORPUS if not _match(k, v, t)]
    recall = (len(CORPUS) - len(misses)) / len(CORPUS)
    assert not misses, f"recall {recall:.1%} ({len(misses)} of {len(CORPUS)} missed): {misses}"


@pytest.mark.parametrize(("kind", "value", "text"), FALSE_POSITIVES)
def test_does_not_match_lookalikes(kind, value, text):
    assert not _match(kind, value, text), f"{kind} {value!r} should not match {text!r}"


def test_no_silent_drops():
    """If the cheap pre-filter says a term is present, the matcher must find it.

    The two disagreeing is what made misses invisible: the source passed the document on and the
    matcher then recorded nothing, with no error anywhere.
    """
    silent = []
    for kind, value, text in CORPUS:
        rendered = render(text)
        term = Term(value, kind, "T")
        if terms_present(rendered, [term]) and not _match(kind, value, text):
            silent.append((kind, text))
    assert not silent, f"pre-filter passed but matcher missed: {silent}"


def test_per_type_recall_is_reported():
    """Each identifier type carries its own weight; none may quietly collapse."""
    by_type: dict[str, list[bool]] = {}
    for kind, value, text in CORPUS:
        by_type.setdefault(kind, []).append(_match(kind, value, text))
    assert sorted(by_type) == ["domain", "email", "keyword", "name", "phone", "username"]
    for kind, results in by_type.items():
        hit = sum(results)
        assert hit == len(results), f"{kind}: only {hit}/{len(results)} matched"
