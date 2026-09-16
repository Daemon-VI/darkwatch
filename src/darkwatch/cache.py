"""On-disk cache for bulk feeds, with conditional GET (ETag / Last-Modified) and a max age.

A feed younger than `max_age_hours` is served from disk with no network call. An older one is
revalidated; a 304 just refreshes the timestamp. If the network fails and a cached copy exists,
the stale copy is used and the caller is told so, which keeps a run useful offline.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import requests

log = logging.getLogger(__name__)


@dataclass
class CachedFeed:
    body: bytes
    fetched_at: float  # epoch seconds of the last successful download or revalidation
    from_network: bool  # True if bytes were downloaded this call
    stale: bool  # True if the network failed and an old copy was used
    note: str = ""


class FeedCache:
    def __init__(self, directory: str | Path):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _paths(self, name: str) -> tuple[Path, Path]:
        return self.dir / f"{name}.body", self.dir / f"{name}.meta.json"

    def get(
        self,
        name: str,
        url: str,
        session: requests.Session,
        *,
        max_age_hours: float,
        timeout: int = 120,
        max_bytes: int = 200_000_000,
        validate: Callable[[bytes], None] | None = None,
    ) -> CachedFeed:
        """`validate(body)` raises ValueError for a body that must not replace the cached copy
        (an HTML maintenance page, an empty body, a JSON error object)."""
        body_p, meta_p = self._paths(name)
        meta: dict = {}
        if meta_p.exists() and body_p.exists():
            try:
                meta = json.loads(meta_p.read_text(encoding="utf-8"))
            except ValueError:
                meta = {}
        now = time.time()
        if meta and now - meta.get("fetched_at", 0) < max_age_hours * 3600:
            return CachedFeed(body_p.read_bytes(), meta["fetched_at"], False, False, "fresh cache")

        headers = {}
        if meta.get("etag"):
            headers["If-None-Match"] = meta["etag"]
        if meta.get("last_modified"):
            headers["If-Modified-Since"] = meta["last_modified"]
        try:
            with session.get(url, headers=headers, timeout=timeout, stream=True) as r:
                if r.status_code == 304 and meta:
                    meta["fetched_at"] = now
                    meta_p.write_text(json.dumps(meta), encoding="utf-8")
                    return CachedFeed(body_p.read_bytes(), now, False, False, "not modified")
                r.raise_for_status()
                buf = bytearray()
                for chunk in r.iter_content(chunk_size=256 * 1024):
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        raise ValueError(f"feed {name} exceeds {max_bytes} bytes")
                if validate is not None:
                    validate(bytes(buf))
                tmp = body_p.with_suffix(".part")
                tmp.write_bytes(bytes(buf))
                tmp.replace(body_p)
                meta = {
                    "url": url,
                    "fetched_at": now,
                    "etag": r.headers.get("ETag", ""),
                    "last_modified": r.headers.get("Last-Modified", ""),
                    "bytes": len(buf),
                }
                meta_p.write_text(json.dumps(meta), encoding="utf-8")
                return CachedFeed(bytes(buf), now, True, False, f"downloaded {len(buf)} bytes")
        except (requests.RequestException, ValueError) as exc:
            if body_p.exists():
                log.warning("feed %s refresh failed (%s); using cached copy", name, exc)
                return CachedFeed(
                    body_p.read_bytes(), meta.get("fetched_at", 0), False, True, f"stale: {exc}"
                )
            raise
