"""fetch_text limits, measured against a local server that misbehaves on purpose."""

import socket
import threading
import time

import pytest
import requests

from darkwatch.fetch import decode_body, fetch_text


@pytest.fixture
def raw_server():
    """A TCP server whose per-connection behaviour a test supplies."""
    behaviours = {}
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            data = conn.recv(4096).decode("latin-1")
            path = data.split(" ")[1] if " " in data else "/"
            handler = behaviours.get(path)
            threading.Thread(target=_run, args=(handler, conn), daemon=True).start()

    def _run(handler, conn):
        try:
            if handler:
                handler(conn)
        except OSError:
            pass
        finally:
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    yield f"http://127.0.0.1:{port}", behaviours
    stop.set()
    srv.close()


def test_trickle_is_cut_at_the_deadline(raw_server):
    base, behaviours = raw_server

    def trickle(conn):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100000\r\n\r\n")
        for _ in range(200):
            conn.sendall(b"x")
            time.sleep(0.1)

    behaviours["/slow"] = trickle
    start = time.monotonic()
    page = fetch_text(requests.Session(), base + "/slow", timeout=5, max_bytes=10**6, deadline=1.0)
    elapsed = time.monotonic() - start
    assert elapsed < 4, elapsed  # not the 20 s the body would take, nor forever
    assert page is None or page.truncated


def test_redirect_body_is_never_read_and_hops_are_routed(raw_server):
    base, behaviours = raw_server

    def huge_redirect(conn):
        conn.sendall(b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 500000000\r\n\r\n")
        conn.sendall(b"y" * 65536)
        time.sleep(2)

    def final(conn):
        body = b"<title>ok</title>hello"
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n" % len(body) + body)

    behaviours["/r"] = huge_redirect
    behaviours["/final"] = final
    hops = []
    session = requests.Session()

    def route(url):
        hops.append(url)
        return session

    start = time.monotonic()
    page = fetch_text(None, base + "/r", timeout=5, max_bytes=10**6, route=route)
    assert page is not None and page.title == "ok" and page.final_url == base + "/final"
    assert hops == [base + "/r", base + "/final"]
    assert time.monotonic() - start < 3


def test_refused_hop_and_non_text(raw_server):
    base, behaviours = raw_server

    def to_onion(conn):
        conn.sendall(b"HTTP/1.1 301 Moved\r\nLocation: http://abcdefghijklmnop.onion/\r\nContent-Length: 0\r\n\r\n")

    def image(conn):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 4\r\n\r\nabcd")

    behaviours["/o"] = to_onion
    behaviours["/img"] = image
    session = requests.Session()
    assert fetch_text(None, base + "/o", timeout=5, max_bytes=100,
                      route=lambda u: None if ".onion" in u else session) is None
    assert fetch_text(session, base + "/img", timeout=5, max_bytes=100) is None
    assert fetch_text(session, "http://127.0.0.1:1/", timeout=2, max_bytes=100) is None


@pytest.mark.parametrize("charset", ["undefined", "idna", "punycode", "bogus-9", "\"windows-1251\""])
def test_decode_body_never_raises(charset):
    raw = "Привет".encode("cp1251")
    out = decode_body(raw, f"text/html; charset={charset}")
    assert isinstance(out, str)
    if "1251" in charset:
        assert out == "Привет"


def test_decode_body_truncated_utf8_is_not_cp1252():
    raw = "José García".encode()[:-1]  # cut inside the last multi-byte character? no: cut the final a
    cut = "José Garcí".encode()[:-1]  # ends inside the two-byte í
    assert decode_body(cut, "text/html", truncated=True) == "José Garc"
    assert decode_body(raw, "text/html") == "José Garcí"
