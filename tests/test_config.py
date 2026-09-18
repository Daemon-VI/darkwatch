from pathlib import Path

import pytest

from darkwatch.config import (
    ALL_SOURCES,
    Target,
    Term,
    find_tor_exe,
    is_onion,
    load_watchlist,
    normalise,
)


def test_load_resolves_paths_and_types(watchlist_file):
    wl = load_watchlist(watchlist_file)
    s = wl.settings
    assert s.sources == ["leaksites"]
    assert s.delay_seconds == 0.0 and isinstance(s.delay_seconds, float)
    assert s.keep_reports == 3
    assert Path(s.db_path).is_absolute() and Path(s.db_path).parent.parent == watchlist_file.parent
    assert Path(s.cache_dir) == watchlist_file.parent / "data" / "cache"
    assert s.notify.min_severity == "HIGH" and s.notify.desktop is False
    assert [t.name for t in wl.targets] == ["Acme Corp", "Jane Doe"]
    assert {t.type for t in wl.terms()} == {"name", "domain", "email", "phone"}


def test_env_supplies_secrets_and_dotenv(watchlist_file, monkeypatch):
    (watchlist_file.parent / ".env").write_text(
        "# comment\nDARKWATCH_HIBP_KEY='k-123'\nDARKWATCH_NTFY_TOPIC=topic-from-env\n"
        "DARKWATCH_SMTP_PORT=2525\nDARKWATCH_SMTP_STARTTLS=false\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("DARKWATCH_SMTP_PORT", raising=False)
    monkeypatch.delenv("DARKWATCH_SMTP_STARTTLS", raising=False)
    wl = load_watchlist(watchlist_file)
    assert wl.settings.hibp_api_key == "k-123"
    assert wl.settings.notify.ntfy_topic == "topic-from-env"
    assert wl.settings.notify.smtp_port == 2525
    assert wl.settings.notify.smtp_starttls is False
    for var in ("DARKWATCH_HIBP_KEY", "DARKWATCH_NTFY_TOPIC", "DARKWATCH_SMTP_PORT", "DARKWATCH_SMTP_STARTTLS"):
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        ("settings:\n  tor_prxy: x\n", "unknown settings"),
        ("settings:\n  sources: [leaksites, psbdmp]\n", "unknown sources"),
        ("settings:\n  tor_manage: sometimes\n", "tor_manage"),
        ("settings:\n  notify:\n    webhook_url: http://x\n", "unknown notify settings"),
        ("extra: 1\n", "unknown top-level keys"),
        ("targets:\n  - name: X\n    emial: [a@b.c]\n", "unknown keys"),
        ("targets:\n  - name: X\n    kind: robot\n", "kind must be"),
        ("targets:\n  - kind: person\n", "needs a `name`"),
        ("targets: []\n", "no targets"),
    ],
)
def test_rejects_bad_watchlists(tmp_path, patch, message):
    base = "targets:\n  - name: Ok\n" if not patch.startswith("targets") else ""
    p = tmp_path / "w.yaml"
    p.write_text(patch + base, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_watchlist(p)


def test_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_watchlist(tmp_path / "nope.yaml")


def test_default_sources_are_all():
    from darkwatch.config import Settings

    assert tuple(Settings().sources) == ALL_SOURCES


def test_target_terms_dedup_and_types():
    t = Target(name="Jane Doe", emails=["A@B.com", "a@b.com "], domains=["*.b.com"], aliases=["JD"])
    terms = t.terms()
    assert [x.type for x in terms] == ["name", "name", "email", "domain"]
    assert terms[2].value == "a@b.com" and terms[3].value == "b.com"
    assert Target(name="X", search_name=False).terms() == []


def test_needles():
    assert Term("+91 98765-43210", "phone", "t").needle == "9876543210"
    assert Term("Acme-Corp Ltd", "name", "t").needle == "acmecorpltd"
    assert Term("a.b@c.io", "email", "t").needle == "abcio"
    assert normalise("ACME_corp  (India)") == "acmecorpindia"


def test_term_validation():
    with pytest.raises(ValueError):
        Term("x", "bogus", "t")
    with pytest.raises(ValueError):
        Term("  ", "email", "t")


def test_is_onion():
    assert is_onion("http://abcdefghijklmnop.onion/")
    assert is_onion("http://sub.abcdefghijklmnop.onion:8080/x")
    assert is_onion("http://" + "a" * 56 + ".onion")
    assert not is_onion("https://ahmia.fi/")
    assert not is_onion("http://evil.com/x.onion")


def test_find_tor_exe(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.delenv("DARKWATCH_TOR_EXE", raising=False)
    project = tmp_path / "ws" / "darkwatch"
    project.mkdir(parents=True)
    assert find_tor_exe("", project) == ""
    bundled = tmp_path / "ws" / "tools" / "tor-15.0.23" / "tor" / "tor.exe"
    bundled.parent.mkdir(parents=True)
    bundled.write_bytes(b"")
    assert find_tor_exe("", project) == str(bundled)
    explicit = tmp_path / "tor.exe"
    explicit.write_bytes(b"")
    assert find_tor_exe(str(explicit), project) == str(explicit)
    monkeypatch.setenv("DARKWATCH_TOR_EXE", str(explicit))
    assert find_tor_exe("", project) == str(explicit)


@pytest.mark.parametrize(
    ("targets", "message"),
    [
        ("  - name: X\n    aliases:\n      -\n      - no\n", "YAML read it as null/yes/no"),
        ("  - name: X\n    phones: [04023456712]\n", "read as a number"),
        ("  - name: X\n    emails: [not-an-email]\n", "is not an email address"),
        ("  - name: X\n    keywords: ['  ']\n", "empty value"),
        ("  - name: [A, B]\n", "exactly one `name`"),
    ],
)
def test_rejects_yaml_values_that_would_become_wrong_terms(tmp_path, targets, message):
    p = tmp_path / "w.yaml"
    p.write_text("targets:\n" + targets, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_watchlist(p)


def test_numeric_setting_errors_name_the_setting(tmp_path):
    p = tmp_path / "w.yaml"
    p.write_text("settings:\n  timeout: soon\ntargets:\n  - name: X\n", encoding="utf-8")
    with pytest.raises(ValueError, match="settings.timeout"):
        load_watchlist(p)


def test_env_example_on_disk_matches_the_one_init_writes():
    """`darkwatch init` writes ENV_EXAMPLE; the repo ships `.env.example` for people who read the
    tree first. They drifted apart once, so the file is the test."""
    from darkwatch.config import ENV_EXAMPLE

    disk = Path(__file__).resolve().parents[1] / ".env.example"
    assert disk.read_text(encoding="utf-8") == ENV_EXAMPLE


def test_env_example_documents_every_secret_the_settings_read():
    """A secret Darkwatch reads from the environment but never documents is a feature nobody can
    turn on."""
    import re

    from darkwatch.config import ENV_EXAMPLE

    source = (Path(__file__).resolve().parents[1] / "src/darkwatch/config.py").read_text(encoding="utf-8")
    used = set(re.findall(r'environ(?:\.get)?[\(\[]["\'](DARKWATCH_[A-Z_]+)', source))
    assert used, "the scan found no environment variables at all"
    documented = set(re.findall(r"^(DARKWATCH_[A-Z_]+)=", ENV_EXAMPLE, re.MULTILINE))
    assert used <= documented, f"undocumented: {sorted(used - documented)}"


def test_example_watchlist_only_names_real_sources():
    from darkwatch.config import ALL_SOURCES, EXAMPLE_WATCHLIST

    line = next(ln for ln in EXAMPLE_WATCHLIST.splitlines() if ln.strip().startswith("sources:"))
    named = [s.strip() for s in line.split("[", 1)[1].rstrip("]").split(",")]
    assert named == list(ALL_SOURCES)


def test_person_sites_accept_a_bare_template_or_a_rule(tmp_path):
    body = """\
settings:
  person_sites:
    - https://plain.example/{username}
    - url: https://soft.example/u/{username}
      name: Soft
      missing_status: 200
      absent_markers: ["user not found"]
targets:
  - name: Jane Doe
    usernames: [jdoe]
"""
    p = tmp_path / "w.yaml"
    p.write_text(body, encoding="utf-8")
    sites = load_watchlist(p).settings.person_sites
    assert sites[0] == {
        "url": "https://plain.example/{username}", "name": "plain.example",
        "missing_status": 404, "absent_markers": [],
    }
    assert sites[1]["name"] == "Soft" and sites[1]["missing_status"] == 200


def test_a_soft_404_site_must_say_how_absence_looks(tmp_path):
    """Without a marker, a site that answers 200 for a free handle reports every handle as a
    profile that exists. That was a real false positive, so it is refused at load time."""
    body = """\
settings:
  person_sites:
    - url: https://soft.example/u/{username}
      missing_status: 200
targets:
  - name: Jane Doe
    usernames: [jdoe]
"""
    p = tmp_path / "w.yaml"
    p.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError, match="absent_markers"):
        load_watchlist(p)


@pytest.mark.parametrize(
    "entry, message",
    [
        ("- url: https://x.example/{username}\n      colour: blue", "unknown keys"),
        ("- https://x.example/profile", "must contain"),
        ("- ftp://x.example/{username}", "http"),
        ("- name: no url here", "no url"),
        ("- url: https://x.example/{username}\n      missing_status: soon", "not a number"),
    ],
)
def test_bad_person_site_entries_are_refused(tmp_path, entry, message):
    body = f"settings:\n  person_sites:\n    {entry}\ntargets:\n  - name: Jane Doe\n    usernames: [jdoe]\n"
    p = tmp_path / "w.yaml"
    p.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_watchlist(p)
