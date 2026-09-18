# Darkwatch — roadmap

v0.3.0 is complete end to end on this laptop: eight sources, managed Tor, the report, triage,
alerts, the daily task, and a local dashboard with keyword search, charts, live scans and
one-off investigations. `PROJECT_STATE.md` has the evidence. The items below extend it; none of
them is needed for it to work.

## Needs Rithik

1. **Subscribe to phone alerts.** Install the ntfy app and subscribe to the topic in
   `watchlist.yaml` (`settings.notify.ntfy_topic`). Delivery to that topic was verified, but
   nothing reaches a phone until it subscribes.
2. **Optional paid HIBP key.** Put `DARKWATCH_HIBP_KEY` in `.env` to add per-email HIBP
   lookups. XposedOrNot already covers the same question for free.
3. **Optional webhook or email.** Set `DARKWATCH_WEBHOOK_URL` or `DARKWATCH_SMTP_*` in `.env`,
   then run `darkwatch notify-test`. Both code paths are tested against local servers, but
   neither has sent to a real Discord channel or mailbox. `.env.example` lists every variable.
4. **Keep personal data out of the public repo.** `Daemon-VI/darkwatch` is public. The
   watchlist, `.env`, `data/` and `reports/` are gitignored. Tests and docs must use made-up
   identifiers only, never real ones.

## Next

- **Company attack surface.** `crt.sh` for certificates issued on a watched domain and its
  subdomains, and `urlscan.io` for pages that reference it. Both are keyless. Together they
  answer "what of ours is exposed", which the current sources only answer for identifiers.
- **First-class `ip` and `wallet` term types.** Both can be watched today as `keyword`, which
  works but is matched as plain text, so `10.0.0.1` also matches inside `110.0.0.15`. They
  deserve their own patterns and weights.
- **`ransomware.live /v2/recentcyberattacks`.** Press-reported incidents, which reach a victim
  that no gang has posted about yet.
- **Paste coverage beyond XposedOrNot.** The onion paste services found on 2026-09-16 are
  either encrypted by design (PrivateBin and similar) or were not reliably reachable.
  `PROJECT_STATE.md` has the details. A Pastebin scraping-API subscription would be the
  reliable clearnet option.
- **A second onion search engine behind Tor.** Ahmia misses forums that block crawlers.
  Candidates must have an abuse filter, the same rule Ahmia was chosen for.
- **Lookalike domains for company targets.** Add a dnstwist-style permutation check with DNS
  resolution, on the clearnet.
- **A second identity source for names.** Every current source keys on an identifier. A person
  with a common name and no leaked email is still hard to answer for.
- **Dashboard: saved searches and a diff view between two runs.** Both are natural once the
  search and timeline endpoints exist, and neither is needed to triage today.
- **Header-phase tarpit.** The fetch watchdog starts once response headers arrive. A server that
  trickles its headers is bounded only by the 45 s per-read timeout, then by Tor shutting down
  at the end of the run. When Tor Browser supplies Tor instead, that second bound is gone.

## Done since v0.2.1

- **Dashboard** (`darkwatch web`, and the "Darkwatch" Desktop shortcut): search, filters with
  live counts, charts, triage, export, live scans over SSE, and deep search.
- **Keyword search** in the CLI too: `darkwatch search` and `darkwatch investigate`.
- **HTML report triage** — superseded. Triage now happens in the dashboard rather than in the
  static report, which stays a document you can archive.
- **Infostealer coverage** (`stealers`) and **username breach coverage** (`leakcheck`).
- **XposedOrNot by domain**, so a company target is not single-sourced on HIBP.
- **24 verified profile sites**, checked in parallel, with per-site absence rules for anything
  the operator adds.

## Not planned

- Logging in to forums or markets, posting, or buying samples. Read-only stays read-only.
- Fetching gang claim pages, images, archives, or full page bodies.
- Any discovery source without an abuse filter.
