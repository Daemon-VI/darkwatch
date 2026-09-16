"""Watchlist + settings loading.

The watchlist is a YAML file with two top-level keys: ``settings`` and ``targets``.
Secrets (API keys, webhook URLs, SMTP passwords) never live in the YAML; they come from
environment variables or a ``.env`` file next to the watchlist. Unknown keys are an error,
because a misspelt setting that is silently ignored is worse than a refusal to start.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field, fields
from pathlib import Path
from urllib.parse import urlparse

import yaml

TERM_TYPES = ("email", "domain", "phone", "username", "name", "keyword")
ALL_SOURCES = ("leaksites", "xposedornot", "hibp", "ahmia", "seeds")


@dataclass(frozen=True)
class Term:
    """One thing to look for, tied back to the target it belongs to."""

    value: str
    type: str  # one of TERM_TYPES
    target: str  # target name

    def __post_init__(self) -> None:
        if self.type not in TERM_TYPES:
            raise ValueError(f"unknown term type {self.type!r}")
        if not self.value.strip():
            raise ValueError("empty term")

    @property
    def needle(self) -> str:
        """Cheap pre-filter key: what must appear in `normalise(text)` (for emails, in
        `normalise(deobfuscate(text))`; for phones, in the digits) for a match to be possible."""
        if self.type == "phone":
            digits = re.sub(r"\D", "", self.value)
            return digits[-10:] if len(digits) > 10 else digits
        return normalise(self.value)


def normalise(text: str) -> str:
    """Lower-case and keep only letters and digits, so `Acme-Corp`, `acme corp`, `ACME_CORP` agree."""
    return re.sub(r"[\W_]+", "", text.lower())


_AT_RE = re.compile(r"\s*[\[\(]\s*at\s*[\]\)]\s*|\s+at\s+", re.IGNORECASE)
_DOT_RE = re.compile(r"\s*[\[\(]\s*dot\s*[\]\)]\s*", re.IGNORECASE)


def deobfuscate(text: str) -> str:
    """`jane [at] mail [dot] com` -> `jane@mail.com`, the forms the email matcher accepts."""
    return _DOT_RE.sub(".", _AT_RE.sub("@", text))


def digits_only(text: str) -> str:
    return re.sub(r"\D", "", text)


@dataclass
class Target:
    name: str
    kind: str = "person"  # person | company
    emails: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)  # other names / brand names
    keywords: list[str] = field(default_factory=list)  # anything else, matched literally
    search_name: bool = True  # whether the display name itself is searched

    def terms(self) -> list[Term]:
        out: list[Term] = []
        if self.search_name:
            out.append(Term(self.name, "name", self.name))
        out.extend(Term(alias, "name", self.name) for alias in self.aliases)
        out.extend(Term(email.strip().lower(), "email", self.name) for email in self.emails)
        out.extend(
            Term(domain.strip().lower().lstrip("*."), "domain", self.name) for domain in self.domains
        )
        out.extend(Term(phone, "phone", self.name) for phone in self.phones)
        out.extend(Term(user, "username", self.name) for user in self.usernames)
        out.extend(Term(kw, "keyword", self.name) for kw in self.keywords)
        seen: set[tuple[str, str]] = set()
        uniq = []
        for t in out:
            key = (t.value.lower(), t.type)
            if key not in seen:
                seen.add(key)
                uniq.append(t)
        return uniq


@dataclass
class NotifySettings:
    min_severity: str = "MEDIUM"
    desktop: bool = True  # Windows toast on this machine; click opens the HTML report
    ntfy_topic: str = ""  # push to a phone via ntfy; the topic name is the only secret
    ntfy_server: str = "https://ntfy.sh"
    webhook_url: str = ""  # from DARKWATCH_WEBHOOK_URL only
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    smtp_starttls: bool = True


# Keys a watchlist may set under `settings.notify`. Secrets are deliberately absent.
NOTIFY_YAML_KEYS = {"min_severity", "desktop", "ntfy_topic", "ntfy_server"}


@dataclass
class Settings:
    # Tor
    tor_proxy: str = "socks5h://127.0.0.1:9050"
    require_tor: bool = True  # skip onion fetches unless the proxy is verified to be a Tor exit
    tor_manage: str = "auto"  # auto: start tor.exe if nothing listens on the proxy port; never
    tor_exe: str = ""  # path to tor.exe; auto-detected when empty
    tor_bootstrap_timeout: int = 180
    tor_workers: int = 4  # parallel onion fetches
    # fetching
    timeout: int = 45
    delay_seconds: float = 2.0  # polite gap between requests to the same clearnet service
    max_page_bytes: int = 2_000_000
    max_results_per_term: int = 5000  # Ahmia listings checked per query (local, cheap); excess is reported
    ahmia_route: str = "auto"  # auto: over Tor when verified, else clearnet; tor: Tor only; clearnet
    onion_fetch_top: int = 5  # top-ranked Ahmia results fetched per query even without a listing match
    max_onion_fetches: int = 150  # hard cap on onion page fetches per run
    max_seed_pages: int = 50
    leak_feed_max_age_hours: float = 12.0  # re-download leak-site feeds at most this often
    ransomlook_days: int = 30
    # what to run
    sources: list[str] = field(default_factory=lambda: list(ALL_SOURCES))
    seeds: list[str] = field(default_factory=list)  # onion/clearnet URLs to fetch directly
    # where things go
    db_path: str = "data/darkwatch.sqlite3"
    reports_dir: str = "reports"
    cache_dir: str = "data/cache"
    tor_data_dir: str = "data/tor"
    keep_reports: int = 60  # timestamped report sets kept; older ones are deleted
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
    # from the environment only
    hibp_api_key: str = ""
    notify: NotifySettings = field(default_factory=NotifySettings)


_SETTINGS_YAML_KEYS = {f.name for f in fields(Settings)} - {"hibp_api_key", "notify"}
_TARGET_KEYS = {f.name for f in fields(Target)}


@dataclass
class Watchlist:
    settings: Settings
    targets: list[Target]
    path: Path

    def terms(self) -> list[Term]:
        out: list[Term] = []
        for t in self.targets:
            out.extend(t.terms())
        return out


def load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines, does not override existing env."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _list(x, what: str = "value", *, text_only: bool = False) -> list[str]:
    """A YAML scalar or list as a list of non-empty strings.

    PyYAML has already converted the values by the time they arrive: `null` is None, `no` is
    False, and an unquoted 04023456712 is an octal int. Those become wrong search terms, so
    they are refused with a hint instead of being stringified.
    """
    if x is None:
        return []
    items = x if isinstance(x, list | tuple) else [x]
    out: list[str] = []
    for v in items:
        if v is None or isinstance(v, bool):
            raise ValueError(f"{what}: {v!r} is not a usable value (YAML read it as null/yes/no); quote it")
        if text_only and isinstance(v, int | float):
            raise ValueError(f'{what}: {v!r} was read as a number; quote it, e.g. "{v}"')
        if isinstance(v, dict | list):
            raise ValueError(f"{what}: expected text, got {type(v).__name__}")
        s = str(v).strip()
        if not s:
            raise ValueError(f"{what}: empty value")
        out.append(s)
    return out


def _bool(x) -> bool:
    if isinstance(x, bool):
        return x
    return str(x).strip().lower() in ("1", "true", "yes", "on")


def _coerce(current, value, what: str = "value"):
    """Coerce a YAML value to the type of the dataclass default it replaces."""
    try:
        if isinstance(current, bool):
            return _bool(value)
        if isinstance(current, int):
            return int(value)
        if isinstance(current, float):
            return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{what}: {value!r} is not a {type(current).__name__}") from exc
    if isinstance(current, list):
        return _list(value, what)
    return "" if value is None else str(value)


def find_tor_exe(configured: str, project_dir: Path) -> str:
    """tor.exe location: setting, then DARKWATCH_TOR_EXE, then PATH, then a sibling tools/ folder."""
    for cand in (configured, os.environ.get("DARKWATCH_TOR_EXE", "")):
        if cand and Path(cand).is_file():
            return str(Path(cand))
    on_path = shutil.which("tor")
    if on_path:
        return on_path
    for base in (project_dir, *project_dir.parents[:2]):
        hits = sorted((base / "tools").glob("tor-*/tor/tor.exe"), reverse=True)
        if hits:
            return str(hits[0])
    return ""


def load_watchlist(path: str | Path) -> Watchlist:
    path = Path(path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"watchlist not found: {path} (run `darkwatch init`)")
    load_dotenv(path.parent / ".env")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"{path.name} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{path.name}: the top level must be a mapping with settings and targets")
    extra_top = set(raw) - {"settings", "targets"}
    if extra_top:
        raise ValueError(f"unknown top-level keys in watchlist: {sorted(extra_top)}")

    s_raw = raw.get("settings") or {}
    if not isinstance(s_raw, dict):
        raise ValueError("settings must be a mapping")
    unknown = set(s_raw) - _SETTINGS_YAML_KEYS - {"notify"}
    if unknown:
        raise ValueError(f"unknown settings: {sorted(unknown)}")
    settings = Settings()
    for key, value in s_raw.items():
        if key != "notify":
            setattr(settings, key, _coerce(getattr(settings, key), value, f"settings.{key}"))
    bad_sources = [s for s in settings.sources if s not in ALL_SOURCES]
    if bad_sources:
        raise ValueError(f"unknown sources {bad_sources}; available: {list(ALL_SOURCES)}")
    if settings.tor_manage not in ("auto", "never"):
        raise ValueError("tor_manage must be 'auto' or 'never'")
    if settings.ahmia_route not in ("auto", "tor", "clearnet"):
        raise ValueError("ahmia_route must be 'auto', 'tor' or 'clearnet'")
    proxy = urlparse(settings.tor_proxy)
    if proxy.scheme != "socks5h" or not proxy.hostname:
        # socks5:// makes PySocks resolve names locally: every onion name would go to the ISP's DNS
        raise ValueError(f"tor_proxy must look like socks5h://127.0.0.1:9050, got {settings.tor_proxy!r}")
    for seed in settings.seeds:
        p = urlparse(seed)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError(f"seed {seed!r} is not an http(s) URL")
    for key in ("timeout", "tor_workers", "max_page_bytes", "tor_bootstrap_timeout"):
        if getattr(settings, key) <= 0:
            raise ValueError(f"settings.{key} must be positive")

    settings.hibp_api_key = os.environ.get("DARKWATCH_HIBP_KEY", "")
    n = settings.notify
    n_raw = s_raw.get("notify") or {}
    if not isinstance(n_raw, dict):
        raise ValueError("settings.notify must be a mapping")
    unknown_n = set(n_raw) - NOTIFY_YAML_KEYS
    if unknown_n:
        raise ValueError(
            f"unknown notify settings: {sorted(unknown_n)} "
            "(webhook and SMTP settings come from DARKWATCH_* environment variables)"
        )
    for key, value in n_raw.items():
        setattr(n, key, _coerce(getattr(n, key), value, f"settings.notify.{key}"))
    n.min_severity = n.min_severity.upper()
    if n.min_severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise ValueError("settings.notify.min_severity must be LOW, MEDIUM, HIGH or CRITICAL")
    n.ntfy_topic = os.environ.get("DARKWATCH_NTFY_TOPIC", n.ntfy_topic)
    n.webhook_url = os.environ.get("DARKWATCH_WEBHOOK_URL", "")
    n.smtp_host = os.environ.get("DARKWATCH_SMTP_HOST", "")
    n.smtp_port = int(os.environ.get("DARKWATCH_SMTP_PORT", "587") or 587)
    n.smtp_user = os.environ.get("DARKWATCH_SMTP_USER", "")
    n.smtp_password = os.environ.get("DARKWATCH_SMTP_PASSWORD", "")
    n.smtp_from = os.environ.get("DARKWATCH_SMTP_FROM", "")
    n.smtp_to = os.environ.get("DARKWATCH_SMTP_TO", "")
    n.smtp_starttls = _bool(os.environ.get("DARKWATCH_SMTP_STARTTLS", "true"))

    targets: list[Target] = []
    t_list = raw.get("targets") or []
    if not isinstance(t_list, list):
        raise ValueError("targets must be a list")
    for t_raw in t_list:
        if not isinstance(t_raw, dict):
            raise ValueError("every target must be a mapping with at least a `name`")
        if "name" not in t_raw:
            raise ValueError("every target needs a `name`")
        unknown_t = set(t_raw) - _TARGET_KEYS
        if unknown_t:
            raise ValueError(f"target {t_raw['name']!r}: unknown keys {sorted(unknown_t)}")
        kind = str(t_raw.get("kind", "person")).lower()
        if kind not in ("person", "company"):
            raise ValueError(f"target {t_raw['name']!r}: kind must be person or company")
        name = _list(t_raw["name"], "target name")
        if len(name) != 1:
            raise ValueError("every target needs exactly one `name`")
        label = f"target {name[0]!r}"
        targets.append(
            Target(
                name=name[0],
                kind=kind,
                emails=_list(t_raw.get("emails"), f"{label} emails", text_only=True),
                domains=_list(t_raw.get("domains"), f"{label} domains", text_only=True),
                phones=_list(t_raw.get("phones"), f"{label} phones", text_only=True),
                usernames=_list(t_raw.get("usernames"), f"{label} usernames"),
                aliases=_list(t_raw.get("aliases"), f"{label} aliases"),
                keywords=_list(t_raw.get("keywords"), f"{label} keywords"),
                search_name=_bool(t_raw.get("search_name", True)),
            )
        )
        for email in targets[-1].emails:
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                raise ValueError(f"{label}: {email!r} is not an email address")
    if not targets:
        raise ValueError("watchlist has no targets")

    base = path.parent
    for attr in ("db_path", "reports_dir", "cache_dir", "tor_data_dir"):
        p = Path(getattr(settings, attr))
        if not p.is_absolute():
            setattr(settings, attr, str(base / p))
    settings.tor_exe = find_tor_exe(settings.tor_exe, base)
    return Watchlist(settings=settings, targets=targets, path=path)


EXAMPLE_WATCHLIST = """\
# Darkwatch watchlist. Only list people and organisations you are authorised to monitor.
settings:
  tor_proxy: socks5h://127.0.0.1:9050   # Tor Browser exposes 9150; a tor.exe started by darkwatch uses 9050
  tor_manage: auto                      # start tor.exe for the run when nothing is listening on that port
  tor_exe: ""                           # path to tor.exe; empty = auto-detect (PATH, ../tools/tor-*/tor/tor.exe)
  require_tor: true                     # never fetch .onion pages unless the proxy is verified to be Tor
  sources: [leaksites, xposedornot, hibp, ahmia, seeds]
  ahmia_route: auto                     # auto: search Ahmia over Tor when Tor is verified; tor; clearnet
  onion_fetch_top: 5                    # Ahmia results fetched per query even when the listing lacks the term
  max_onion_fetches: 150
  seeds: []                             # onion / clearnet URLs you want fetched and scanned every run
  notify:
    min_severity: MEDIUM                # only alert on new hits at or above this
    desktop: true                       # Windows notification; click it to open the report
    ntfy_topic: ""                      # phone push via https://ntfy.sh; use a long random topic

targets:
  - name: Example Person
    kind: person
    emails: [example.person@example.com]
    phones: ["+91 98765 43210"]
    usernames: [example_person]
    aliases: []
  - name: Example Company Pvt Ltd
    kind: company
    domains: [example.com]
    aliases: [ExampleCo]
    keywords: []
"""

def is_onion(url: str) -> bool:
    """True when the URL's host is a .onion name. Decided on the parsed hostname, so
    `...onion?page=2`, `...onion#top`, `user@x.onion` and `x.onion.` all count: anything that
    would otherwise be resolved through the system DNS must go to Tor instead."""
    try:
        host = (urlparse(url.strip()).hostname or "").rstrip(".")
    except ValueError:
        return False
    return host.endswith(".onion")
