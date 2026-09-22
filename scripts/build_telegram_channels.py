"""Rebuild src/darkwatch/data/telegram_channels.json from the deepdarkCTI index.

    uv run python scripts/build_telegram_channels.py

Only public channels are kept (``t.me/<handle>``): invite links (``t.me/+...``, ``joinchat``) need
an account to read, and Darkwatch never joins anything. Infostealer channels are listed first.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path

import requests

BASE = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/"
FILES = (("telegram_infostealer.md", "infostealer"), ("telegram_threat_actors.md", "threat-actor"))
OUT = Path(__file__).resolve().parents[1] / "src" / "darkwatch" / "data" / "telegram_channels.json"
HANDLE = re.compile(r"^https?://t\.me/(?:s/)?([A-Za-z][A-Za-z0-9_]{3,})/?$")


def main() -> None:
    seen: set[str] = set()
    channels: list[dict] = []
    for name, kind in FILES:
        text = requests.get(BASE + name, timeout=30).text
        for line in text.splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) < 3:
                continue
            m = HANDLE.match(cells[0])
            if not m or m.group(1).lower() in seen or m.group(1).lower() == "joinchat":
                continue
            seen.add(m.group(1).lower())
            channels.append({"handle": m.group(1), "name": cells[2], "kind": kind, "status": cells[1]})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "source": "https://github.com/fastfire/deepdarkCTI",
        "built": dt.datetime.now(dt.UTC).date().isoformat(),
        "channels": channels,
    }, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    kinds = {k: sum(c["kind"] == k for c in channels) for _, k in FILES}
    print(f"wrote {len(channels)} channels {kinds} to {OUT}")


if __name__ == "__main__":
    main()
