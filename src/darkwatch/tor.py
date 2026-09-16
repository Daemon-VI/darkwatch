"""Tor: HTTP sessions (clearnet and SOCKS5h), an 'is this really Tor?' check, and a managed tor.exe.

The managed process exists so a scheduled run needs nothing else running. It is started only
when nothing already listens on the configured SOCKS port, it is told who owns it
(`__OwningControllerProcess`) so it exits on its own if darkwatch dies, and it is stopped when
the run ends. A Tor that was already running (Tor Browser, a service) is used and left alone.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from pathlib import Path
from urllib.parse import urlparse

import requests

from .config import Settings

log = logging.getLogger(__name__)

CHECK_URL = "https://check.torproject.org/api/ip"
BOOTSTRAP_RE = re.compile(r"Bootstrapped (\d+)%")


def make_session(settings: Settings, via_tor: bool) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": settings.user_agent,
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
            "Accept-Language": "en-US,en;q=0.5",
        }
    )
    if via_tor:
        # socks5h: DNS is resolved by the proxy, which is what makes .onion resolve at all
        s.proxies.update({"http": settings.tor_proxy, "https": settings.tor_proxy})
    s.trust_env = False  # ignore system proxy env vars; we choose explicitly
    adapter = requests.adapters.HTTPAdapter(pool_connections=8, pool_maxsize=max(8, settings.tor_workers))
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def check_tor(session: requests.Session, timeout: int = 30) -> dict:
    """Ask the Tor Project whether our exit is a Tor exit. Returns {'IsTor', 'IP', 'error'}."""
    try:
        r = session.get(CHECK_URL, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        return {"IsTor": bool(data.get("IsTor")), "IP": data.get("IP", "?"), "error": ""}
    except Exception as exc:  # noqa: BLE001
        return {"IsTor": False, "IP": "?", "error": f"{type(exc).__name__}: {exc}"}


def parse_proxy(url: str) -> tuple[str, int]:
    p = urlparse(url)
    if p.scheme != "socks5h":
        # socks5:// resolves names locally, which leaks every onion name to the system DNS
        raise ValueError(f"tor_proxy must be a socks5h:// URL, got {url!r}")
    return p.hostname or "127.0.0.1", p.port or 9050


def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class TorStartError(RuntimeError):
    pass


class TorProcess:
    """A tor.exe child process that is considered ready once it logs `Bootstrapped 100%`."""

    def __init__(
        self,
        command: list[str],
        *,
        timeout: float = 180,
        progress: Callable[[str], None] = lambda m: None,
    ):
        self.command = command
        self.timeout = timeout
        self.progress = progress
        self.proc: subprocess.Popen[str] | None = None
        self.lines: deque[str] = deque(maxlen=200)
        self.percent = 0
        self._ready = threading.Event()
        self._reader: threading.Thread | None = None

    @classmethod
    def for_settings(cls, settings: Settings, progress: Callable[[str], None] = lambda m: None) -> TorProcess:
        exe = settings.tor_exe
        if not exe or not Path(exe).is_file():
            raise TorStartError(
                "tor.exe not found. Set settings.tor_exe, set DARKWATCH_TOR_EXE, put tor on PATH, "
                "or unpack the Tor Expert Bundle into ../tools/tor-<version>/"
            )
        host, port = parse_proxy(settings.tor_proxy)
        data_dir = Path(settings.tor_data_dir)
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TorStartError(f"cannot create the Tor data directory {data_dir}: {exc}") from exc
        cmd = [
            exe,
            "--SocksPort", f"{host}:{port}",
            "--DataDirectory", str(data_dir),
            "--ClientOnly", "1",
            "--Log", "notice stdout",
            "--__OwningControllerProcess", str(os.getpid()),
        ]
        geo = Path(exe).parent.parent / "data"
        if (geo / "geoip").is_file():
            cmd += ["--GeoIPFile", str(geo / "geoip"), "--GeoIPv6File", str(geo / "geoip6")]
        return cls(cmd, timeout=settings.tor_bootstrap_timeout, progress=progress)

    def _read(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for line in self.proc.stdout:
            line = line.rstrip()
            self.lines.append(line)
            m = BOOTSTRAP_RE.search(line)
            if m:
                pct = int(m.group(1))
                if pct > self.percent:
                    self.percent = pct
                    self.progress(f"tor: bootstrapped {pct}%")
                if pct >= 100:
                    self._ready.set()
            elif "[err]" in line or "[warn]" in line:
                log.info("tor: %s", line)

    def start(self) -> None:
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        self.progress(f"tor: starting {Path(self.command[0]).name}")
        started = time.monotonic()
        try:
            self.proc = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=flags,
            )
        except OSError as exc:  # blocked by Defender/AppLocker, not an executable, missing DLL
            raise TorStartError(f"could not start {self.command[0]}: {exc}") from exc
        self._reader = threading.Thread(target=self._read, name="tor-log", daemon=True)
        self._reader.start()
        while not self._ready.wait(0.25):
            if self.proc.poll() is not None:
                tail = "\n".join(list(self.lines)[-8:])
                raise TorStartError(f"tor exited with code {self.proc.returncode}:\n{tail}")
            if time.monotonic() - started > self.timeout:
                self.stop()
                raise TorStartError(
                    f"tor did not finish bootstrapping in {self.timeout:.0f}s (reached {self.percent}%). "
                    "If this network blocks Tor, configure bridges in a torrc."
                )
        self.bootstrap_seconds = time.monotonic() - started
        self.progress(f"tor: ready in {self.bootstrap_seconds:.1f}s")

    def stop(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self.progress("tor: stopped")


@contextlib.contextmanager
def ensure_tor(settings: Settings, progress: Callable[[str], None] = lambda m: None) -> Iterator[dict]:
    """Make sure something is listening on the SOCKS port for the duration of the block.

    Yields {'managed': bool, 'bootstrap_seconds': float | None, 'error': str}.
    Never raises for a Tor that cannot start; the caller decides what to do without it.
    """
    host, port = parse_proxy(settings.tor_proxy)
    state: dict = {"managed": False, "bootstrap_seconds": None, "error": ""}
    if port_open(host, port):
        progress(f"tor: using the proxy already listening on {host}:{port}")
        yield state
        return
    if settings.tor_manage != "auto":
        state["error"] = f"nothing listening on {host}:{port} and tor_manage is {settings.tor_manage!r}"
        yield state
        return
    tor: TorProcess | None = None
    try:
        tor = TorProcess.for_settings(settings, progress)
        tor.start()
        state.update(managed=True, bootstrap_seconds=round(tor.bootstrap_seconds, 1))
    except TorStartError as exc:
        state["error"] = str(exc)
        progress(f"tor: {exc}")
        if tor is not None:
            tor.stop()
        tor = None
    except BaseException:
        if tor is not None:
            tor.stop()
        raise
    try:
        yield state
    finally:
        if tor is not None:
            tor.stop()
