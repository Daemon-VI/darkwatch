"""Fetch a page as *text only*, with hard limits.

Rules that matter for a dark web tool, each learned from a review finding:
- Only text/html, text/plain, XHTML and JSON are read. No images, archives or binaries.
- Bytes are capped, and so is wall-clock time: a watchdog shuts the socket down when a page
  trickles in slower than `deadline` allows. requests' timeout is per socket read, and a
  non-chunked body blocks until a whole chunk arrives, so a check inside the loop is not enough.
- Redirects are followed by hand. A 3xx body is never read (requests would read it whole,
  with no cap), and every hop is routed again, so a clearnet page that redirects to an onion
  is never looked up through the system resolver.
- Any decoding problem degrades to a best-effort decode. It never ends the calling source.
- Callers keep only matched snippets, never page bodies.
"""

from __future__ import annotations

import codecs
import logging
import re
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)

TEXT_TYPES = ("text/html", "text/plain", "application/xhtml+xml", "application/json")
REDIRECTS = (301, 302, 303, 307, 308)
META_CHARSET_RE = re.compile(rb"<meta[^>]+charset=[\"']?([\w-]+)", re.IGNORECASE)
HEADER_CHARSET_RE = re.compile(r"charset=[\"']?([\w-]+)", re.IGNORECASE)

Router = Callable[[str], "requests.Session | None"]


@dataclass
class Page:
    url: str  # the URL asked for
    final_url: str  # after redirects
    title: str
    text: str
    status: int
    content_type: str
    truncated: bool = False
    html: str = ""  # only when keep_html=True (seeds need the links)


def decode_body(raw: bytes, content_type: str, *, truncated: bool = False) -> str:
    """Declared charset (header, then <meta>), else UTF-8, else cp1252. Never raises.

    requests assumes ISO-8859-1 for text/* without a charset, which turns UTF-8 onion pages
    into mojibake, so its guess is not used. A declared charset that is not a usable text
    codec ("undefined", "idna", "bogus") is ignored. A body cut at the byte cap may end inside a
    multi-byte character; that tail is dropped rather than forcing the whole page to cp1252.
    """
    declared = ""
    m = HEADER_CHARSET_RE.search(content_type)
    if m:
        declared = m.group(1)
    else:
        mm = META_CHARSET_RE.search(raw[:4096])
        if mm:
            declared = mm.group(1).decode("ascii", "ignore")
    if declared:
        try:
            return raw.decode(declared, errors="replace")
        except (LookupError, UnicodeError, ValueError, TypeError):
            pass
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if truncated:
        try:
            return codecs.getincrementaldecoder("utf-8")().decode(raw, final=False)
        except UnicodeDecodeError:
            pass
    return raw.decode("cp1252", errors="replace")


def html_to_text(html: str) -> tuple[str, str]:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg", "img", "video", "audio", "iframe"]):
        tag.decompose()
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    text = soup.get_text(" ", strip=True)
    return title, " ".join(text.split())


def _abort(resp: requests.Response) -> None:
    """Break a blocked read from the watchdog thread: shut the socket down, then close."""
    conn = getattr(resp.raw, "_connection", None)
    sock = getattr(conn, "sock", None)
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    try:
        resp.close()
    except Exception as exc:  # noqa: BLE001 - best effort from a timer thread
        log.debug("watchdog close failed: %s", type(exc).__name__)


def fetch_text(
    session: requests.Session | None,
    url: str,
    *,
    timeout: int,
    max_bytes: int,
    deadline: float | None = None,
    route: Router | None = None,
    max_redirects: int = 5,
    keep_html: bool = False,
) -> Page | None:
    """GET `url` and return its text, or None when it is unavailable, not text, or refused.

    `route(url)` picks the session for each hop (None refuses the hop); without it every hop
    uses `session`. `deadline` bounds the whole download in seconds (default 3 x timeout).
    Never raises for anything the remote side can cause.
    """
    limit = deadline if deadline is not None else timeout * 3
    started = time.monotonic()
    current = url
    for _hop in range(max_redirects + 1):
        sess = route(current) if route is not None else session
        if sess is None:
            log.info("refused %s: no safe route for it", current)
            return None
        try:
            r = sess.get(current, timeout=timeout, stream=True, allow_redirects=False)
        except (requests.RequestException, ValueError) as exc:
            log.info("fetch failed %s: %s", current, type(exc).__name__)
            return None
        remaining = limit - (time.monotonic() - started)
        watchdog = threading.Timer(max(remaining, 0.1), _abort, args=(r,))
        watchdog.daemon = True
        watchdog.start()
        try:
            if r.status_code in REDIRECTS and r.headers.get("Location"):
                nxt = urljoin(current, r.headers["Location"])
                if urlparse(nxt).scheme not in ("http", "https"):
                    log.info("refused redirect from %s to %s", current, nxt)
                    return None
                current = nxt
                continue  # the finally block closes r without reading its body
            ctype = (r.headers.get("Content-Type") or "").lower()
            if not ctype.startswith(TEXT_TYPES):
                log.info("skip non-text %s (%s)", current, ctype or "no content-type")
                return None
            buf = bytearray()
            truncated = False
            try:
                for chunk in r.iter_content(chunk_size=8192):
                    buf.extend(chunk)
                    if len(buf) >= max_bytes or time.monotonic() - started > limit:
                        truncated = True
                        break
            except Exception as exc:  # noqa: BLE001 - watchdog abort or a broken stream
                if not buf:
                    log.info("fetch aborted %s: %s", current, type(exc).__name__)
                    return None
                truncated = True
            if truncated:
                log.info("truncated %s at %d bytes after %.0fs", current, len(buf), time.monotonic() - started)
            body = decode_body(bytes(buf[:max_bytes]), ctype, truncated=truncated)
            if ctype.startswith(("text/html", "application/xhtml")):
                title, text = html_to_text(body)
            else:
                title, text = "", " ".join(body.split())
            return Page(
                url=url, final_url=current, title=title, text=text, status=r.status_code,
                content_type=ctype, truncated=truncated, html=body if keep_html else "",
            )
        finally:
            watchdog.cancel()
            r.close()
    log.info("too many redirects from %s", url)
    return None
