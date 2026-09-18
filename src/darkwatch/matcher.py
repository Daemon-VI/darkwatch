"""Find watchlist terms in text, pull a snippet, and score how bad it looks.

Scoring is deliberately simple and explainable: a base score per term type, plus one point
per *signal group* found near the match (credentials, financial data, government IDs, sale
language, doxxing language), plus a source weight. The report shows the signals so a human
can see why something is CRITICAL rather than trusting a number.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import pairwise

from .config import Term

SNIPPET_RADIUS = 160

# Characters that carry no meaning but break a match: zero-width joiners and spaces, the soft
# hyphen, the BOM. Leak posts and forum software insert them, deliberately or not.
INVISIBLE = re.compile(r"[\u00ad\u200b-\u200f\u2060\ufeff]")
# Dashes and spaces that look like ASCII but are not.
LOOKALIKES = {
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-", "\u2015": "-",
    "\u2212": "-", "\u00a0": " ", "\u202f": " ", "\u2009": " ", "\uff0e": ".", "\uff20": "@",
}
_LOOKALIKE_RE = re.compile("|".join(map(re.escape, LOOKALIKES)))

# user:pass / email:pass lines. Two or more of them mean a credential dump, whatever the page
# calls itself, which is what the word-list signals alone kept missing.
COMBO_LINE = re.compile(r"(?m)^[^\s:|]{3,64}[:|][^\s:|]{4,64}\s*$")
COMBO_INLINE = re.compile(r"[\w.+-]{1,64}@[\w.-]{2,63}\.[A-Za-z]{2,12}:[^\s:]{4,64}")


def normalise_text(text: str) -> str:
    """Fold away what only defeats matching: invisible characters, look-alike dashes and spaces.

    Applied once to a document before matching, so snippets are the folded text too. NFKC is
    deliberately not used wholesale: it rewrites ligatures and some scripts in ways that would
    change what the evidence says.
    """
    if not text:
        return text
    folded = INVISIBLE.sub("", text)
    if any(ch in folded for ch in LOOKALIKES):
        folded = _LOOKALIKE_RE.sub(lambda m: LOOKALIKES[m.group(0)], folded)
    return unicodedata.normalize("NFC", folded)


def combo_lines(text: str) -> int:
    """How many `user:pass`-shaped lines the text holds."""
    return len(COMBO_LINE.findall(text)) + len(COMBO_INLINE.findall(text))

# Each group: (name, regex over the surrounding window). Case-insensitive.
SIGNAL_GROUPS: list[tuple[str, re.Pattern[str]]] = [
    (
        "credentials",
        re.compile(
            r"\b(password\w*|passwd|pwd|pass\s*[:=]|hash(?:es|ed)?|bcrypt|md5|sha1|sha256|combo(?:list)?|"
            r"logins?|credentials?|creds|cookies?|sessions?|tokens?|api[_ -]?keys?|"
            r"security questions?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "financial",
        re.compile(
            r"\b(credit ?cards?|debit ?cards?|cvv|cvc|card ?numbers?|iban|swift|upi|bank ?accounts?|"
            r"account ?numbers?|routing|bin\s?\d{6}|fullz|payment cards?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "government_id",
        re.compile(
            r"\b(aadhaar|aadhar|pan ?card|pan ?number|passport|ssn|social security|driver'?s? ?licen[cs]e|"
            r"voter ?ids?|national ?ids?|government issued ids?|tax ids?|dob|dates? of birth)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "sale",
        re.compile(
            r"\b(for sale|selling|buy now|price|btc|bitcoin|monero|xmr|usd|escrow|vendor|listing|"
            r"database dump|db dump|dump|leak(?:ed|s)?|breach(?:ed)?|exfil)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "dox",
        re.compile(
            r"\b(dox+(?:ed|ing)?|home address(?:es)?|physical address(?:es)?|residen(?:ce|tial)|"
            r"family|relatives|swat|personal info(?:rmation)?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "access",
        re.compile(
            r"\b(rdp|vpn access|initial access|shell|webshell|admin panel|backdoor|ransom(?:ware)?|"
            r"citrix|fortinet|domain admin)\b",
            re.IGNORECASE,
        ),
    ),
]

BASE_SCORE = {"email": 2, "phone": 3, "domain": 2, "username": 1, "name": 1, "keyword": 1}
# How much the kind of evidence adds. Keys are sources.DOC_SOURCES.
SOURCE_WEIGHT = {
    # A ransomware gang posted it: that is the incident, on its own. This weight is what makes a
    # leak-site post serious, rather than signal words found in Darkwatch's own sentence.
    "leaksite": 4,
    # A machine you used was infected and its saved credentials were taken: at least as
    # actionable as a leak-site post, and it is happening now rather than to a service.
    "stealer": 4,
    "onion": 2,
    "seed": 2,
    "breach": 2,
    "paste": 2,
    "ahmia-index": 1,
    "site": 0,  # a public profile the person put up is expected; only its contents raise it
    "file": 0,
}

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# Evidence at least this old scores one point lower and carries the pseudo-signal "dated".
DATED_AFTER_YEARS = 3
YEAR_RE = re.compile(r"(?<!\d)(19[89]\d|20\d\d)(?!\d)")


def evidence_year(value: str | None) -> int | None:
    if not value:
        return None
    m = YEAR_RE.search(str(value))
    return int(m.group(1)) if m else None


def _phone_in_context(matched: str, before: str) -> bool:
    """A phone match counts fully when it is written as a phone: a country/trunk prefix, digit
    grouping, or a phone word just before it."""
    if matched.startswith(("+", "0")) or re.search(r"\d[\s\-.()]\d", matched):
        return True
    return bool(PHONE_CONTEXT.search(before))


def signals_in(text: str) -> list[str]:
    """Signal groups present in `text`, by word list plus one structural rule.

    The structural rule exists because a plaintext combolist says nothing about itself: it is
    5,000 lines of `address:password` with no word a regex would catch.
    """
    found = [name for name, rx in SIGNAL_GROUPS if rx.search(text)]
    if "credentials" not in found and combo_lines(text) >= 2:
        found.append("credentials")
        found.sort(key=lambda n: [g[0] for g in SIGNAL_GROUPS].index(n))
    return found


def severity_from_score(score: int) -> str:
    if score >= 7:
        return "CRITICAL"
    if score >= 5:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"


def severity_rank(sev: str) -> int:
    return SEVERITIES.index(sev.upper()) if sev.upper() in SEVERITIES else 0


@dataclass
class Match:
    term: Term
    start: int
    end: int
    snippet: str
    signals: list[str] = field(default_factory=list)
    score: int = 0
    severity: str = "LOW"


PHONE_SEP = r"[\s\-\.\(\)]{0,3}"


# `example[.]com`, `example(.)com`, `example [dot] com`: how a domain is written on a leak site
# or in a threat-intel post so it is not auto-linked. Matching only the literal dot missed all of it.
DEFANGED_DOT = r"(?:\.|\s*[\[({]\s*(?:\.|dot)\s*[\])}]\s*|\s+dot\s+)"
HANDLE_CONTEXT = re.compile(
    r"[@/\\]$|^[@/\\:]|(?:user(?:name)?|handle|nick|profile|account|by)\W{0,3}$", re.IGNORECASE
)
PHONE_CONTEXT = re.compile(
    r"(?:phone|mobile|cell|tel|telephone|whatsapp|contact|call|sms|otp|number)\W{0,12}$", re.IGNORECASE
)


def _phone_pattern(value: str) -> re.Pattern[str]:
    """The last 10 digits with any separators, optionally preceded by the number's own country
    code (with or without + / 00) or a trunk 0. Digits glued to the number on either side that
    are not that prefix reject the match, so 19876543210 does not match +91 98765 43210."""
    digits = re.sub(r"\D", "", value)
    if len(digits) < 6:
        return re.compile(rf"(?<!\d){re.escape(digits)}(?!\d)" if digits else re.escape(value))
    core = digits[-10:] if len(digits) > 10 else digits
    prefix = digits[:-10] if len(digits) > 10 else ""
    body = PHONE_SEP.join(core)
    options = [r"0" + PHONE_SEP]
    if prefix:
        options.insert(0, r"(?:\+|00)?" + PHONE_SEP.join(prefix) + PHONE_SEP)
    return re.compile(rf"(?<!\d)(?:{'|'.join(options)})?{body}(?!\d)")


def _email_pattern(value: str) -> re.Pattern[str]:
    local, _, domain = value.lower().partition("@")
    at = r"(?:@|\s*[\[({]\s*at\s*[\])}]\s*|\s+at\s+)"
    dom = DEFANGED_DOT.join(re.escape(p) for p in domain.split("."))
    # the tail guard rejects longer domains: jane@yahoo.com must not match jane@yahoo.com.br
    return re.compile(rf"(?<![\w.+-]){re.escape(local)}{at}{dom}(?![\w-]|\.[\w-])", re.IGNORECASE)


def _domain_pattern(value: str) -> re.Pattern[str]:
    r"""example.com, also inside sub.example.com; never notexample.com or example.com.evil.net.

    No subdomain group: `(?:[\w-]+\.)*` in front made long dotted runs backtrack quadratically
    (16 KB took 1.2 s), and it never changed which occurrences match, because a domain after
    "label." is preceded by ".", which the lookbehind already allows."""
    labels = value.lower().split(".")
    body = DEFANGED_DOT.join(re.escape(part) for part in labels)
    return re.compile(rf"(?<![\w-]){body}(?![\w-]|\.[\w-])", re.IGNORECASE)


WORD_SEP = r"[\s_.,&'/\-]+"
# Between two words: _ - , & \' / whitespace, or a dot that is NOT a sentence end. Allowing
# ". " made "Ask Jane. Doe will confirm" match the name "Jane Doe", so it is excluded.
JOIN_SEP = r"(?:[_,&'/\-]|\.(?!\s)|\s)+"
# Long enough that gluing two parts cannot collide with an unrelated word ("Al Ice" must not
# match "Alice", but "Acme Inc" should match "AcmeInc").
GLUE_MIN = 3


def _words_pattern(value: str) -> re.Pattern[str]:
    """Words in order, separated by any of _ - , & \' / space or a non-final dot.

    The separator is optional between two parts that are both at least GLUE_MIN characters, so a
    term entered as "Acme Inc" also matches "Acme, Inc.", "Acme-Inc" and "AcmeInc" — the same
    equivalence `config.normalise` uses for the pre-filter, which previously passed documents the
    matcher then silently dropped.
    """
    parts = [p for p in re.split(WORD_SEP, value.strip()) if p]
    if not parts:
        return re.compile(re.escape(value))
    body = re.escape(parts[0])
    for previous, part in pairwise(parts):
        glue = "*" if len(previous) >= GLUE_MIN and len(part) >= GLUE_MIN else "+"
        body += f"(?:{JOIN_SEP}){glue}" + re.escape(part)
    return re.compile(r"(?<!\w)" + body + r"(?!\w)", re.IGNORECASE)


def compile_term(term: Term) -> re.Pattern[str]:
    if term.type == "email":
        return _email_pattern(term.value)
    if term.type == "phone":
        return _phone_pattern(term.value)
    if term.type == "domain":
        return _domain_pattern(term.value)
    return _words_pattern(term.value)


class Matcher:
    def __init__(self, terms: list[Term]):
        self.terms = terms
        self._patterns = [(t, compile_term(t)) for t in terms]

    def find(
        self,
        text: str,
        *,
        source: str = "file",
        max_per_term: int | None = 5,
        signal_text: str | None = None,
        title: str = "",
        evidence_date: str | None = None,
    ) -> list[Match]:
        """Every occurrence of every term (up to `max_per_term` each; None means all).

        Signals come from the page title plus the text around each match, or from
        `signal_text` when the caller has context that describes the exposure better (a
        breach's data classes, a whole leak-site post). Evidence dated `DATED_AFTER_YEARS` or
        more years ago loses a point and is marked "dated".
        """
        year = evidence_year(evidence_date)
        dated = year is not None and datetime.now(UTC).year - year >= DATED_AFTER_YEARS
        text = normalise_text(text)
        out: list[Match] = []
        if not text:
            return out
        fixed_signals = None if signal_text is None else signals_in(signal_text)
        for term, pat in self._patterns:
            for n, m in enumerate(pat.finditer(text), start=1):
                s = max(0, m.start() - SNIPPET_RADIUS)
                e = min(len(text), m.end() + SNIPPET_RADIUS)
                window = text[s:e]
                if fixed_signals is not None:
                    signals = list(fixed_signals)
                else:
                    signals = signals_in(f"{title} {window}" if title else window)
                base = BASE_SCORE.get(term.type, 1)
                before = text[max(0, m.start() - 24):m.start()]
                credit = len(signals)
                if term.type == "phone" and not _phone_in_context(m.group(0), before):
                    # a bare ten-digit run is as likely to be an order id as a phone number
                    base = 1
                    signals = [*signals, "uncorroborated"]
                    credit = 0
                elif term.type == "username" and " " not in term.value and not HANDLE_CONTEXT.search(before):
                    # a one-word handle matches the ordinary word; do not let a market page's
                    # surrounding words push "shadow" to CRITICAL on their own
                    signals = [*signals, "uncorroborated"]
                    credit = 0
                score = base + credit + SOURCE_WEIGHT.get(source, 1)
                if dated:
                    score -= 1
                    signals.append("dated")
                out.append(
                    Match(
                        term=term,
                        start=m.start(),
                        end=m.end(),
                        snippet=("…" if s > 0 else "") + window + ("…" if e < len(text) else ""),
                        signals=signals,
                        score=score,
                        severity=severity_from_score(score),
                    )
                )
                if max_per_term is not None and n >= max_per_term:
                    break
        return out
