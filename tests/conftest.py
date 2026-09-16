"""Shared fixtures: a tiny local HTTP server whose responses a test scripts, and a watchlist on disk."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


class Recorder:
    """Scripted responses keyed by path; records every request it sees."""

    def __init__(self):
        self.routes: dict[str, list[tuple[int, dict, bytes]]] = {}
        self.requests: list[dict] = []

    def add(self, path: str, status: int = 200, body: bytes | str | dict | list = b"", headers: dict | None = None):
        if isinstance(body, dict | list):
            body = json.dumps(body).encode()
            headers = {"Content-Type": "application/json", **(headers or {})}
        elif isinstance(body, str):
            body = body.encode()
        self.routes.setdefault(path, []).append((status, headers or {}, body))

    def respond(self, path: str) -> tuple[int, dict, bytes]:
        queue = self.routes.get(path) or self.routes.get(path.split("?")[0])
        if not queue:
            return 404, {"Content-Type": "text/plain"}, b"no route"
        return queue.pop(0) if len(queue) > 1 else queue[0]


@pytest.fixture
def http_server():
    rec = Recorder()

    class Handler(BaseHTTPRequestHandler):
        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            rec.requests.append(
                {"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body}
            )
            status, headers, payload = rec.respond(self.path)
            self.send_response(status)
            headers = {"Content-Type": "text/html; charset=utf-8", **headers}
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        do_GET = do_POST = do_HEAD = _handle

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    rec.base = f"http://127.0.0.1:{server.server_address[1]}"
    yield rec
    server.shutdown()
    server.server_close()


WATCHLIST = """\
settings:
  tor_manage: never
  tor_proxy: socks5h://127.0.0.1:1
  sources: [leaksites]
  delay_seconds: 0
  keep_reports: 3
  notify:
    min_severity: HIGH
    desktop: false
targets:
  - name: Acme Corp
    kind: company
    domains: [acme.example]
    aliases: [AcmeCo]
  - name: Jane Doe
    kind: person
    emails: [jane.doe@mail.example]
    phones: ["+91 98765 43210"]
"""


@pytest.fixture
def watchlist_file(tmp_path: Path, monkeypatch) -> Path:
    for var in ("DARKWATCH_HIBP_KEY", "DARKWATCH_NTFY_TOPIC", "DARKWATCH_WEBHOOK_URL", "DARKWATCH_SMTP_HOST",
                "DARKWATCH_TOR_EXE"):
        monkeypatch.delenv(var, raising=False)
    p = tmp_path / "watchlist.yaml"
    p.write_text(WATCHLIST, encoding="utf-8")
    return p
