# Darkwatch — project state

Last updated: 2026-09-16 (v0.2.0, complete end to end on this laptop).

## What it is

Darkwatch is a dark web exposure monitor. It reads a YAML watchlist of the people and companies
it protects, with their names, emails, phones, domains and usernames. It then:

1. Searches ransomware leak-site trackers, breach and paste data, Ahmia's onion index, and the
   onion pages behind it. Onion pages are fetched over a `tor.exe` that Darkwatch starts and
   stops itself.
2. Scores each hit and de-duplicates it in SQLite.
3. Writes a Markdown, HTML and JSON report with an action list for every hit.
4. Alerts through a Windows notification and an ntfy phone push. Webhook and email are optional.
5. Runs daily from Task Scheduler.

It lives at `C:\Users\Rishi\darkwatch`: Python 3.12, `uv`, with the code in `src/darkwatch/`. It is
a git repo on `main`, pushed to the private GitHub repo `Daemon-VI/darkwatch`. The live watchlist holds Rithik's own identifiers and is
gitignored.

## Verified on 2026-09-16

| Check | Result |
|---|---|
| `uv run pytest -q` | 133 passed, about 23 s |
| `uv run ruff check src tests` | clean |
| Tor Expert Bundle 15.0.23 | GPG signature good (key EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290); installed at `C:\Users\Rishi\tools\tor-15.0.23` |
| `darkwatch check-tor` (managed Tor) | ready in 43.0 s on a fresh data dir, 4.6 to 18.6 s after that; the exit was confirmed as Tor by check.torproject.org; tor.exe exits after the run and uses about 110 MB of RAM while it runs |
| Validation watchlist (public data only) | see the next table |
| Real watchlist, manual run (run 2) | 180 s, no errors, Tor verified, 0 hits |
| Scheduled task, `schedule run-now` (runs 3 and 4) | Last Result 0 both times, with no console window; log written to `data/logs/darkwatch.log`; no tor.exe or pythonw.exe left afterwards; next run is 2026-09-17 09:00 |
| Alerts | See the note below the tables. |

**Alerts:**

- The Windows notification was confirmed by reading the notification-history API, which showed the tags `selftest1`, `selftest` and `run4`.
- The ntfy push was confirmed by polling the topic, which returned the test message at priority 5.
- Webhook and SMTP were tested only against local servers: an `http.server` instance, and aiosmtpd with STARTTLS turned off.

**Validation run.** The validation watchlist is kept outside the repo and uses only public data:

- **Company targets:** a hospital that ransomware.live lists publicly, plus canva.com.
- **Email:** the reserved address `test@example.com`.
- **Keyword:** `example.com`, which appears on real onion pages.

| Source | Result (calibrated run) |
|---|---|
| leaksites | 31,828 unique posts checked in 1.2 s from cache (21.7 MB download on the first run). The hospital's rhysida leak-site post came back CRITICAL, with the financial, government_id, sale and access signals. |
| xposedornot | 214 breaches for test@example.com, in 10 s |
| hibp (keyless domain) | The Canva 2019 breach, MEDIUM and marked dated |
| ahmia + Tor | 1,329 listings checked; 12 of 15 onion pages fetched (15 of 15 on the first run). canva.com was found on an onion "Leaks" index page listing "Canva.Com 60,390,129 2023-06-19", scored HIGH. |

**Real watchlist.** Rithik's name, alias, email, phone and two usernames were checked against every source:

| Source | Result |
|---|---|
| Leak sites | 0 matches among 31,831 posts |
| XposedOrNot | no match: `check-email` returned "Not found" |
| Ahmia | 2,512 listings checked over the onion service, 19 of 25 onion pages fetched, 0 real hits |

A run on 2026-09-16 did produce 8 false hits, and they triggered one false alert. The cause is in the next section, and the hits are marked false_positive.

## Code review

The code was reviewed area by area, and each top finding was then checked by trying to refute it. Everything real was
fixed, and each fix has a regression test:

- **Rich markup crash.** A hostile title containing `[/b/]` crashed `run` before the report and
  alerts, so that alert was lost for good. Fix: untrusted text is now printed as `Text`, and
  reports and alerts come before any table.
- **Phones in glued form were missed.** Forms like `+919876543210`, `00919…` and `0…` did not match.
- **The domain regex backtracked quadratically.** 16 KB took 1.2 s, so a 2 MB page could take hours.
  The same case now takes 0.004 s on 200 KB.
- **`jane@yahoo.com` matched `jane@yahoo.com.br`.**
- **Only the first 5 occurrences on a page were scored.**
- **The v2 to v3 migration could file stronger, untriaged evidence under "resolved".**
- **YAML scalar problems.** `null`, `no` and unquoted leading-zero phones became wrong terms.
  Invalid YAML also produced a traceback instead of exit 2.
- **`require_tor: false` was a silent no-op.**
- **Page fetching.**
  - A `charset=undefined` page crashed the whole source.
  - There was no overall time limit per page; a trickling page stalled the run.
  - Redirect bodies were read in full with no cap.
  - Onion names could reach the system DNS through `?`/`#` URLs or a clearnet redirect.

  Fixes: a watchdog now shuts the socket down at the deadline, redirects are followed by hand
  with each hop routed again, and `is_onion` checks the parsed hostname.
- **Listings were dropped on a loose pre-filter match.** The drop decision now uses the matcher's
  own patterns.
- **A bad feed body could replace the good cached one.** Feeds are now validated before they are
  written.
- **`tor.exe` OSError aborted every source,** clearnet ones included.
- **Tracebacks were lost under pythonw.** They now go to the log file.
- **The PID lock could be blocked by PID reuse.** It is now an OS byte-range lock, which Windows
  drops when the process dies. This was tested by killing a lock holder.
- **Privacy and safety.**
  - SMTP did not verify certificates.
  - `socks5://` was accepted.
  - Markdown reports rendered hostile titles as images or links.
  - ntfy pushes named the target.
  - Failed webhook and ntfy calls logged the secret URL or topic.
- **Ahmia searches went out over the clearnet.** The skeptic called this a documented choice, but
  it was fixed anyway after a live test: searches now go over Tor, to the onion service first and
  then ahmia.fi through an exit, and never fall back to clearnet while Tor is verified.
- **A bug that only showed up live.**
  - On the onion service, an empty results page links to itself through its time filters, and
    the fallback parser treated those self-links as results. That produced the 8 false hits and
    one false alert in run 4, with no identifiers in the alert.
  - Fix: Ahmia's own hosts are excluded, a regression test covers it, and the 8 hits are marked
    false_positive with a note.
  - Checked live afterwards: run 5 (Ahmia only) went over the onion service, checked 2,504
    listings, found 0 new hits, reported 0 errors, and took 197.7 s.

## Decisions made while building

- **psbdmp is dead, so paste coverage comes from elsewhere.**
  - psbdmp.ws no longer resolves, and psbdmp.cc returns 404 on every API path. Paste coverage now
    comes from XposedOrNot's paste index, plus HIBP pastes with a key.
  - Onion paste services found through Ahmia were checked over Tor on 2026-09-16:
    - Most "paste" listings are clones of carding marketplaces.
    - PrivateBin, Disroot and DarkPaste encrypt their pastes by design.
    - Pasteelo's `list.php` links all resolved to one "Top Black Markets" directory page.
    - DarkPaste's `trending.php` returned 504.

  None is worth seeding.
- **ransomware.live's search API allows one request per minute** (observed as HTTP 429), so the
  bulk `victims.json` file is used instead.
- **Ahmia search is a loose keyword match,** so every listing is checked locally.
- **Calibration against real data.** This added page titles to the signal text, whole-post
  signals for leak sites, a stable hit identity, the dated penalty, and a charset fix for UTF-8
  onion pages.

## Not verified

- **Real delivery to a Discord or Slack webhook, or to an SMTP mailbox.** Neither is configured; the code paths are tested only against local servers.
- **Per-email HIBP lookups.** They need a paid key.
- **A seeds run against real sites.** No seeds are configured; the code is tested only against a local server.
- **Phone push reaching an actual phone.** The ntfy server received the message, but no phone is subscribed yet.

## Known limits

- Ahmia's coverage is Ahmia's: forums that block crawlers are not in its index.
- Onion page fetches fail 20 to 30% of the time on any given run (11 of 17, 12 of 15, 19 of 25),
  because onion services are unreliable. Each failure costs up to the 45 s timeout.
- `.env.example` in the repo lacks `DARKWATCH_NTFY_TOPIC` and `DARKWATCH_SMTP_STARTTLS`. `.env*`
  files are only edited by hand in this workspace, so the README documents them and `darkwatch init` writes a
  complete template.
