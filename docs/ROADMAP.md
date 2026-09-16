# Darkwatch — roadmap

v0.2.0 is complete end to end on this laptop: every source, managed Tor, the report, triage,
alerts, and the daily task. `PROJECT_STATE.md` has the evidence. The items below extend it;
none of them is needed for it to work.

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

- **Paste coverage beyond XposedOrNot.** The onion paste services found on 2026-09-16 are
  either encrypted by design (PrivateBin and similar) or were not reliably reachable.
  `PROJECT_STATE.md` has the details. A Pastebin scraping-API subscription would be the
  reliable clearnet option.
- **A second onion search engine behind Tor.** Ahmia misses forums that block crawlers.
  Candidates must have an abuse filter, the same rule Ahmia was chosen for.
- **Lookalike domains for company targets.** Add a dnstwist-style permutation check with DNS
  resolution, on the clearnet.
- **HTML report triage.** The report is static. Triage happens in the CLI (`ack`, `resolve`,
  `false-positive`).
- **Header-phase tarpit.** The fetch watchdog starts once response headers arrive. A server that
  trickles its headers is bounded only by the 45 s per-read timeout, then by Tor shutting down
  at the end of the run. When Tor Browser supplies Tor instead, that second bound is gone.

## Not planned

- Logging in to forums or markets, posting, or buying samples. Read-only stays read-only.
- Fetching gang claim pages, images, archives, or full page bodies.
- Any discovery source without an abuse filter.
