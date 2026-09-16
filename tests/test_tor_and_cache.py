import socket
import sys
import time

import pytest
import requests

from darkwatch.cache import FeedCache
from darkwatch.config import Settings
from darkwatch.tor import TorProcess, TorStartError, ensure_tor, parse_proxy, port_open

FAKE_TOR = """
import sys, time
mode = sys.argv[1]
print("Sep 16 [notice] Tor 0.4.9 opening log", flush=True)
if mode == "fail":
    print("Sep 16 [err] Could not bind to 127.0.0.1:9050", flush=True)
    sys.exit(1)
for pct in (0, 10, 50, 100) if mode == "ok" else (0, 10):
    print(f"Sep 16 [notice] Bootstrapped {pct}% (x): y", flush=True)
    time.sleep(0.05)
time.sleep(30)
"""


@pytest.fixture
def fake_tor(tmp_path):
    script = tmp_path / "fake_tor.py"
    script.write_text(FAKE_TOR, encoding="utf-8")
    return lambda mode: [sys.executable, str(script), mode]


def test_parse_proxy():
    assert parse_proxy("socks5h://127.0.0.1:9150") == ("127.0.0.1", 9150)
    assert parse_proxy("socks5h://localhost") == ("localhost", 9050)
    with pytest.raises(ValueError):
        parse_proxy("http://127.0.0.1:8080")


def test_port_open():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    try:
        assert port_open("127.0.0.1", port)
    finally:
        srv.close()
    assert not port_open("127.0.0.1", port, timeout=0.2)


def test_tor_process_ready_and_stop(fake_tor):
    seen = []
    tor = TorProcess(fake_tor("ok"), timeout=20, progress=seen.append)
    tor.start()
    try:
        assert tor.percent == 100
        assert "tor: bootstrapped 100%" in seen
        assert tor.bootstrap_seconds < 20
        assert tor.proc.poll() is None
    finally:
        tor.stop()
    assert tor.proc.poll() is not None
    assert "tor: stopped" in seen


def test_tor_process_exit_is_reported(fake_tor):
    tor = TorProcess(fake_tor("fail"), timeout=20)
    with pytest.raises(TorStartError, match="Could not bind"):
        tor.start()


def test_tor_process_timeout(fake_tor):
    tor = TorProcess(fake_tor("stall"), timeout=1.5)
    t0 = time.monotonic()
    with pytest.raises(TorStartError, match="reached 10%"):
        tor.start()
    assert time.monotonic() - t0 < 10
    assert tor.proc.poll() is not None  # killed on timeout


def test_for_settings_requires_exe(tmp_path):
    with pytest.raises(TorStartError, match="tor.exe not found"):
        TorProcess.for_settings(Settings(tor_exe="", tor_data_dir=str(tmp_path)))
    exe = tmp_path / "tor" / "tor.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "geoip").write_text("")
    tp = TorProcess.for_settings(
        Settings(tor_exe=str(exe), tor_proxy="socks5h://127.0.0.1:9123", tor_data_dir=str(tmp_path / "td"))
    )
    cmd = tp.command
    assert cmd[0] == str(exe)
    assert cmd[cmd.index("--SocksPort") + 1] == "127.0.0.1:9123"
    assert "--__OwningControllerProcess" in cmd and "--GeoIPFile" in cmd
    assert (tmp_path / "td").is_dir()


def test_ensure_tor_uses_existing_listener_and_never_mode(tmp_path):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    try:
        s = Settings(tor_proxy=f"socks5h://127.0.0.1:{port}", tor_manage="never")
        with ensure_tor(s) as state:
            assert state == {"managed": False, "bootstrap_seconds": None, "error": ""}
    finally:
        srv.close()
    with ensure_tor(s) as state:
        assert "tor_manage is 'never'" in state["error"]
    s_auto = Settings(tor_proxy=f"socks5h://127.0.0.1:{port}", tor_manage="auto", tor_exe="")
    with ensure_tor(s_auto) as state:
        assert "tor.exe not found" in state["error"] and not state["managed"]


def test_ensure_tor_manages_and_stops(monkeypatch, fake_tor, tmp_path):
    started = []

    def fake_for_settings(settings, progress):
        tp = TorProcess(fake_tor("ok"), timeout=20, progress=progress)
        started.append(tp)
        return tp

    monkeypatch.setattr(TorProcess, "for_settings", staticmethod(fake_for_settings))
    s = Settings(tor_proxy="socks5h://127.0.0.1:1", tor_manage="auto")
    with ensure_tor(s) as state:
        assert state["managed"] and state["bootstrap_seconds"] is not None and not state["error"]
        assert started[0].proc.poll() is None
    assert started[0].proc.poll() is not None


# ----------------------------------------------------------------------------- feed cache
def test_feed_cache_download_fresh_revalidate_and_stale(tmp_path, http_server):
    http_server.add("/feed", 200, b"v1", {"ETag": '"e1"', "Last-Modified": "Wed, 16 Sep 2026 14:00:09 GMT"})
    cache = FeedCache(tmp_path / "c")
    sess = requests.Session()
    url = http_server.base + "/feed"

    first = cache.get("feed", url, sess, max_age_hours=1)
    assert (first.body, first.from_network, first.stale) == (b"v1", True, False)

    fresh = cache.get("feed", url, sess, max_age_hours=1)
    assert fresh.note == "fresh cache" and len(http_server.requests) == 1

    http_server.routes["/feed"] = [(304, {}, b"")]
    reval = cache.get("feed", url, sess, max_age_hours=0)
    assert reval.note == "not modified" and reval.body == b"v1"
    assert http_server.requests[-1]["headers"].get("If-None-Match") == '"e1"'
    assert http_server.requests[-1]["headers"].get("If-Modified-Since")

    http_server.routes["/feed"] = [(200, {"ETag": '"e2"'}, b"v2")]
    changed = cache.get("feed", url, sess, max_age_hours=0)
    assert changed.body == b"v2" and changed.from_network

    http_server.routes["/feed"] = [(503, {}, b"down")]
    stale = cache.get("feed", url, sess, max_age_hours=0)
    assert stale.stale and stale.body == b"v2" and "stale" in stale.note


def test_feed_cache_without_copy_raises(tmp_path, http_server):
    http_server.add("/gone", 500, b"x")
    with pytest.raises(requests.HTTPError):
        FeedCache(tmp_path).get("gone", http_server.base + "/gone", requests.Session(), max_age_hours=1)


def test_feed_cache_size_cap(tmp_path, http_server):
    http_server.add("/big", 200, b"x" * 5000)
    with pytest.raises(ValueError, match="exceeds"):
        FeedCache(tmp_path).get("big", http_server.base + "/big", requests.Session(), max_age_hours=1, max_bytes=100)
