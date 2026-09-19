"""Public Telegram channels — where a great deal of leak and infostealer trading now happens.

Telegram has no public global search without an account, but every *public* channel exposes a
read-only web preview at ``https://t.me/s/<channel>``, and that preview honours ``?q=<term>``,
which searches the channel's own history. So for each watched identifier Darkwatch asks each
channel "have you ever posted this?", reads the matching messages as text, and never logs in,
joins, or sees anything a logged-out browser would not.

The channel list is `data/telegram_channels.json`, built from the community-maintained
deepdarkCTI index (threat-actor and infostealer channels). Infostealer channels come first, so a
capped run still covers the ones that carry credentials. A channel that is gone, private, or has
no matching post costs one request and is dropped.

Only strong identifiers are searched — email, domain, username, name, keyword. A phone number or
a bare name fragment matches too much on a busy channel to be worth the requests; the matcher
would reject the noise anyway, but the requests are the cost here, so they are not spent.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from importlib import resources

from bs4 import BeautifulSoup

from ..config import Settings, Term, normalise
from . import Document, SourceContext

log = logging.getLogger(__name__)

PREVIEW = "https://t.me/s/{channel}"
QUERY_TYPES = ("email", "domain", "username", "name", "keyword")
MAX_MESSAGES_PER_HIT = 8  # messages kept per (channel, term); enough to judge, bounded in the DB
MESSAGE_CHARS = 500


def load_channels() -> list[dict]:
    """The shipped channel list, infostealer channels first."""
    try:
        raw = json.loads(
            resources.files("darkwatch.data").joinpath("telegram_channels.json").read_text("utf-8")
        )
    except (FileNotFoundError, ValueError, ModuleNotFoundError):
        return []
    channels = [c for c in raw.get("channels", []) if isinstance(c, dict) and c.get("handle")]
    channels.sort(key=lambda c: 0 if c.get("kind") == "infostealer" else 1)
    return channels


def parse_messages(html: str) -> list[tuple[str, str]]:
    """(message_url, text) for each message on a t.me/s preview page."""
    soup = BeautifulSoup(html, "html.parser")
    out: list[tuple[str, str]] = []
    for wrap in soup.select(".tgme_widget_message"):
        body = wrap.select_one(".tgme_widget_message_text")
        if body is None:
            continue
        text = body.get_text(" ", strip=True)
        if not text:
            continue
        link = wrap.get("data-post")  # "channel/123"
        url = f"https://t.me/{link}" if link else ""
        out.append((url, text))
    return out


def messages_with_term(html: str, term: Term) -> list[tuple[str, str]]:
    """Preview messages whose normalised text actually contains the term.

    Telegram's own search is fuzzy and returns near matches, so — exactly as the Ahmia source
    does — the returned page is re-checked locally against the term before anything is kept.
    """
    needle = term.needle
    if not needle:
        return []
    hits = []
    for url, text in parse_messages(html):
        if needle in normalise(text):
            hits.append((url, text[:MESSAGE_CHARS]))
    return hits


class TelegramSource:
    name = "telegram"
    description = "public Telegram threat-actor and infostealer channels, read over the web with no login"

    def unavailable_reason(self, settings: Settings) -> str:
        return "" if load_channels() else "channel list missing"

    def discover(self, terms: list[Term], ctx: SourceContext) -> Iterator[Document]:
        s = ctx.settings
        wanted = [t for t in terms if t.type in QUERY_TYPES]
        if not wanted:
            return
        channels = load_channels()
        cap = s.telegram_max_channels
        if cap and cap > 0:
            channels = channels[:cap]
        if not channels:
            ctx.error("telegram: no channel list shipped")
            return

        checked = dead = found = 0
        for c in channels:
            handle = c["handle"]
            base = PREVIEW.format(channel=handle)
            alive = True
            for term in wanted:
                if not alive:
                    break
                ctx.throttle("telegram", max(s.delay_seconds, 0.7))
                ctx.progress(f"telegram: {handle} / {term.value}")
                try:
                    r = ctx.clear.get(base, params={"q": term.value}, timeout=s.timeout)
                except Exception as exc:  # noqa: BLE001 - one channel must not end the source
                    ctx.error(f"telegram: {handle}: {type(exc).__name__}")
                    alive = False
                    continue
                checked += 1
                # a private/removed channel redirects to its join page or a generic t.me shell
                if r.status_code != 200 or "tgme_widget_message" not in r.text:
                    dead += 1
                    alive = False  # no public history: the other terms would fail the same way
                    continue
                for url, text in messages_with_term(r.text, term)[:MAX_MESSAGES_PER_HIT]:
                    found += 1
                    kind = c.get("kind", "channel")
                    yield Document(
                        url=url or f"{base}?q={term.value}",
                        title=f"Telegram {kind} channel @{handle}",
                        text=f"Posted in the public Telegram channel @{handle} ({kind}): {text}",
                        source="telegram",
                        # infostealer channels post credential dumps; that is the signal, and it
                        # comes from what the channel is, not from words the matcher must find
                        signal_text="credentials passwords logins dump leak" if kind == "infostealer" else "",
                        meta={"channel": handle, "kind": kind, "query": term.value},
                    )
        ctx.stats.note = (
            f"{found} message(s) across {checked - dead}/{len(channels)} live channel(s), "
            f"{dead} gone or private"
        )
