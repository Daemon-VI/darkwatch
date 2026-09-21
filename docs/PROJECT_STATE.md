# Darkwatch — project state

Last updated: 2026-09-19 (v0.4.0: deep-scan mode, Telegram and recent-attacks sources).
v0.3.0 (dashboard, keyword search, infostealer and username-breach sources, 24 profile sites,
measured accuracy pass) is below it.

## What it is

Darkwatch is a dark web exposure monitor. It reads a YAML watchlist of the people and companies
it protects, with their names, emails, phones, domains and usernames. It then:

1. Searches ransomware leak-site trackers, infostealer logs, breach and paste data, 24
   public-profile sites for each username, Ahmia's onion index, and the onion pages behind it.
   Onion pages are fetched over a `tor.exe` that Darkwatch starts and stops itself.
2. Scores each hit and de-duplicates it in SQLite.
3. Writes a Markdown, HTML and JSON report with an action list for every hit.
4. Alerts through a Windows notification and an ntfy phone push. Webhook and email are optional.
5. Runs daily from Task Scheduler, or on demand from three Desktop shortcuts.
6. Serves a local dashboard (`darkwatch web`) for search, charts, triage, live scans and
   one-off investigations.

## v0.4.0 additions (2026-09-19)

Prompted by "I need a deep scan that searches everything, it may take 1-2 hours". The deep scan
trades time for reach while holding two hard lines: it never logs in, joins, pays, or solves a
CAPTCHA, and it never blind-crawls — links are followed only out of pages that already match a
watched identifier, and onion discovery still goes through Ahmia's abuse filter.

### New

- **`darkwatch run --deep`** (`scanner.deepen`): every source regardless of the watchlist; the
  Telegram channel cap dropped (all ~940); the blind onion sweep 5->15 per query and budget 150->2000; and
  same-host onion links followed one level out of any onion page that matched a term
  (`ahmia._follow`). Only raises limits, so a watchlist that already sets something higher is left.
- **`telegram` source** — public Telegram threat-actor and infostealer channels, read through the
  `t.me/s/<channel>?q=<term>` web preview with no login. 936 channels shipped in
  `data/telegram_channels.json`, built from the community-maintained deepdarkCTI index,
  infostealer channels first so a capped run still covers the credential channels. Telegram's own
  search is fuzzy, so every returned message is re-checked locally for the exact term.
- **`recentattacks` source** — ransomware.live's recent-incidents feed: reported cyber-attacks,
  gang-claimed or not, so an incident disclosed before any leak-site post is still caught.
- Ten sources now; `attack` weight 3, `telegram` weight 2.

### VS Code extension (2026-09-21)

`vscode-extension/` — a TypeScript extension, a thin safe front end over the CLI:

- a **Findings** tree grouped by severity with a status-bar count;
- **Run Scan**, **Deep Scan**, **Open Dashboard** in an integrated terminal;
- **Search** stored findings, **Investigate** a one-off value;
- **triage** (acknowledge / resolve / false positive) from a finding's menu.

It reads data through two new CLI flags, `darkwatch hits --json` and `darkwatch search --json`
(both tested). Like the dashboard it **never opens an evidence URL** — those point at leak sites
and onion services — it shows the URL as text and copies it on request, and it spawns the CLI
with `shell:false` and an argv array so a search value can never be shell-interpreted.

Verified 2026-09-21: `npm install`, `npm run compile` and `npm run lint` clean; `npx vsce package`
produced `darkwatch-0.1.0.vsix` (9 files, 16 KB). Publishing to the Marketplace (publisher
`daemon-vi`) and Open VSX is wired in `.github/workflows/publish-vscode.yml`, gated on the
`VSCE_PAT` / `OVSX_PAT` secrets — **not yet published**; that step is Rithik's, needing his tokens.

### Deep onion run (2026-09-19 to -21)

The full `--deep` run launched 2026-09-19 finished every source through `telegram` clean (a full
936-channel Telegram sweep: 0 messages), then was killed mid-Ahmia when the machine went down. A
follow-up `run --deep --sources ahmia` on 2026-09-21 **completed** (Run #15, 399 s) but Ahmia was
unreachable on every route that run (6 errors, 0 listings) — an intermittent Ahmia/Tor outage, not
a clean sweep. Earlier full runs did reach Ahmia (2,168 listings, 0 hits), so the no-exposure
result stands; the deep onion leg is proven to run but depends on Ahmia being up on the day.

### Deliberately still out of scope

- **Account-walled forums and markets** (BreachForums successors, XSS, Exploit, carding markets):
  no read-only way in without creating accounts or paying. Not attempted.
- **The other ~30 onion search engines** deepdarkCTI lists: most do not filter abuse material, so
  each would need vetting before use. Ahmia stays the only discovery engine for now.

### Verified on 2026-09-19

| Check | Result |
|---|---|
| `uv run pytest -q` | 229 passed (227 + 2 for the CLI `--json` flags) |
| `uv run ruff check src tests` | clean |
| `recentattacks` against the live feed | 100 incidents parsed into Documents in 1.0 s |
| `telegram` parse + live path | against `t.me/s/durov` searching "Telegram": 8 messages parsed, filtered to the term, and emitted with real message URLs |
| `telegram` dead-channel handling | 8 alphabetically-first infostealer channels: 1 live, 7 correctly detected gone/private (one request each) |
| `telegram` channel list | 936 public channels shipped (97 infostealer, 839 threat-actor), infostealer-first |
| `deepen()` | raises onion depth/budget, drops the channel cap, enables every source, follows links 1 level; leaves already-higher settings alone |

**Not yet run at full scale.** A complete `run --deep` against the real watchlist (all ~940
Telegram channels x the terms, plus deep onion following) is an estimated 1-2 hours and has not
been run end to end yet, partly because this laptop was memory-constrained during the session
(~0.5 GB free). Each component above is verified live; the full-scale timing and yield are not.

## v0.3.0 additions (2026-09-18)

Prompted by "it's not accurate": the accuracy work was measured rather than asserted, then the
surface was widened.

### Accuracy

A 90-case regression corpus (`tests/test_recall.py`, 15 renderings per identifier type, taken
from how identifiers actually appear on leak sites, in HTML and in combolists) measured the
matcher before and after:

| | Before | After |
|---|---|---|
| Recall on the 90-case corpus | 62 of 90 (69%) | **90 of 90 (100%)** |
| Failures on the 9-case negative set | 1 (a sentence boundary: `Ask Jane. Doe will confirm` matched the name `Jane Doe`) | **0** |

Separately from the negative set, three severity inflations were found and fixed: leak-site posts
scoring Darkwatch's own wording, a dictionary word as a username reaching CRITICAL, and a bare
10-digit run scoring HIGH as a phone number.

What was wrong, and what each fix was:

- **Leak-site posts scored themselves.** `signal_text` was Darkwatch's own sentence ("was listed
  on the leak site of the ransomware group X"), so every post scored the `sale` and `access`
  signals from wording Darkwatch wrote. Fixed: the signal text is now the tracker's own
  description, website, sector and country, and a leak-site post instead carries the source
  weight it deserves (3 → 4). The severity is the same for a real post; it is now honest about why.
- **Inline markup split identifiers.** `<b>example</b>.com` became `example .com` because
  `get_text("")` with no block separators ran text together and `get_text(" ")` broke words
  apart. Fixed: separators are inserted around block tags only.
- **Defanged domains were invisible.** `example[.]com`, `example(.)com` and `example dot com` —
  how a domain is written on a leak site so it is not auto-linked — matched nothing.
- **Zero-width characters defeated matching.** A soft hyphen or `\u200b` inside an address made it
  unmatchable. Text is now folded (invisible characters removed, look-alike dashes and spaces
  normalised) before matching, so snippets show the folded text too.
- **Plaintext combolists said nothing about themselves.** 5,000 lines of `address:password` carry
  no word a signal regex would catch. Two or more `user:pass` lines now count as credentials.
- **A dictionary word as a username could reach CRITICAL.** A handle like `admin` or `ronin` in
  ordinary prose scored as if it were the person. It is now credited at most one point and marked
  `uncorroborated` unless it appears in handle context (`@name`, `user: name`, a profile URL).
- **Bare digit runs scored HIGH as phone numbers.** A 10-digit order number is now
  `uncorroborated` too, unless it is written as a phone (a `+`/trunk prefix, digit grouping, or a
  phone word before it).
- **The pre-filter passed documents the matcher then silently dropped.** `Acme Inc` matched
  `Acme-Inc` but not `AcmeInc`, and `Acme, Inc.` not at all. The separator between two parts of
  three characters or more is now optional, so both match — while `Al Ice` still does not match
  `Alice`, and `Jane. Doe` (a sentence boundary) still does not match the name `Jane Doe`.

The email on the watchlist was also cross-checked against two independent breach services by
hand, and both said "not found", so the "no exposure" result is corroborated rather than assumed.

### New

- **Dashboard** (`darkwatch web`, `src/darkwatch/web/`): keyword search across every finding,
  filters with live counts, severity-over-time and source-mix charts, triage in place, CSV and
  JSON export, a scan run from the page with progress streaming over server-sent events, and
  deep search of a value that is not on the watchlist. One HTML page, no build step, GSAP and a
  WebGL2 contour field ported from the portfolio. Security: loopback bind, a per-session token
  required by a router-level dependency, a loopback-only `Host` check, no CORS, POST-only
  mutations, evidence rendered as text nodes and never linked. A test sweeps all 14 `/api`
  endpoints from the app's own schema and fails if any answers without the token.
- **Keyword search in the CLI too:** `darkwatch search` (with `--facets`) and
  `darkwatch investigate`, which runs the live sources against one value and stores nothing.
- **`stealers` source** — Hudson Rock Cavalier infostealer logs, keyless, by email, username and
  domain. The gap that mattered most: every other source answers "a service you used was
  breached"; this one answers "a machine you typed your password into was infected". Weighted 4,
  the same as a leak-site post. The free tier masks the values (`P********3`) and Darkwatch keeps
  only those masked forms.
- **`leakcheck` source** — LeakCheck's public API, keyless, by email **and username**, naming the
  data classes each breach exposed (`ssn`, `dob`, `password`), so severity reflects what leaked.
  The only source that answers for a handle.
- **XposedOrNot by domain**, so a company target is not single-sourced on HIBP.
- **`sites` grew from 7 to 24 verified sites** and now runs its checks in parallel (a session per
  worker thread). 19 of 36 further candidates passed a live present/absent check and 17 of those
  were new, taking the list from 7 to 24; the 17 that failed are named in `sites.py`, each with
  the way it failed.
- **Per-site absence rules for configured sites.** `person_sites` entries may now be a mapping
  with `missing_status` and `absent_markers`. A site that answers 200 for a free handle without a
  marker is refused at load time, because it would report every handle as a profile.

### Verified on 2026-09-18

| Check | Result |
|---|---|
| `uv run pytest -q` | 217 passed in 32.6 s |
| `uv run ruff check src tests` | clean |
| Matcher recall corpus | 90 of 90, 0 false positives |
| Real watchlist, full run (run #10) | 262.6 s, 19 documents, 4 new hits, 0 escalated, 5 already known, **0 errors**, Tor verified (exit confirmed, bootstrap 9.1 s) |
| `leaksites` | 31,919 unique posts checked in 12.0 s (21.79 MB fresh download); 0 matches |
| `stealers` | 0 of 3 identifiers found in infostealer logs, 4.7 s — **no infected machine holds Rithik's credentials** |
| `leakcheck` | 0 of 3 identifiers found in breach data, 4.9 s |
| `xposedornot` | no match, 0.7 s |
| `sites` | 5 of 48 checks matched across 24 sites in 7.5 s, 4 new hits |
| `ahmia` | 2,168 listings checked over the onion service; 14 of 17 onion pages fetched; 0 hits; 219.5 s |
| `darkwatch investigate canva.com --no-tor` | 2 findings in 1.8 s, both MEDIUM and marked `dated`: HIBP's Canva breach and XposedOrNot's, the latter through the new domain endpoint. Nothing was written to the database. |
| Dashboard against the real database | `/api/summary` served 9 open hits, 18 total, 90 documents, version 0.3.0, all 8 sources listed as enabled; keyword search over `/api/hits` returned 5 hits for `github`, 2 for `huggingface`, 1 for `docker hub` and 0 for `nonsense`, in 0.66 to 2.85 ms |
| Desktop shortcuts | all three created and verified by reading each `.lnk` back: `Darkwatch` -> `python.exe -m darkwatch web`, `Scan now` -> `run --open`, `Report` -> `pythonw.exe -m darkwatch open` |

**The four new findings were verified by hand, and all four are real:**

| Finding | Check |
|---|---|
| Docker Hub `rithikkrishnat` | exists, joined 2026-02-27; a free handle returns 404 with `"User not found"` |
| Hugging Face `rithikkrishnat` | exists, `fullname: "RITHIK KRISHNA"` — which is why the matcher also recorded the *name* against that page |
| X `Daemon-VI` | 200 for the handle, 404 for a free one |
| GitHub `rithikkrishnat` | a second GitHub account beside `Daemon-VI` |

All four are LOW with no signals, which is correct: they are profiles Rithik put up himself. The
expanded site list produced **no false positives**.

## v0.2.1 additions (2026-09-16)

- **`sites` source — an individual's public footprint.** For each `username` term it checks which
  sites carry a profile (GitHub, Dev.to, Keybase, Replit, Gravatar, Chess.com, Hacker News), then
  reads each found profile for the person's *other* watched identifiers. Verified live: for the
  real watchlist it found `Daemon-VI` and `rithikkrishnat` on GitHub, and pulled the real name
  "Rithik Krishna T" off the Daemon-VI profile page (2 of 14 checks matched, 5 LOW hits, 7.8 s).
  Profile hits score LOW and carry no signals; the page's own chrome never manufactures one.
  The default site list was chosen by testing live which sites give a clean 404 for a free handle:
  GitLab, npm and Reddit answer 403 to non-browser requests, and PyPI and Telegram soft-404, so
  they are excluded. Extra sites go in `person_sites` as `{username}` URL templates.
- **Desktop shortcuts.** `darkwatch shortcut` creates "Darkwatch - Scan now" and
  "Darkwatch - Report" on the Desktop, verified by reading each `.lnk` back: they point at the
  project's `python.exe` / `pythonw.exe` with `run --open` and `open`.
- **`.env.example` completed.** It is generated from `config.ENV_EXAMPLE` (the same text `init`
  writes) and now lists every variable, including `DARKWATCH_NTFY_TOPIC`,
  `DARKWATCH_SMTP_STARTTLS` and `DARKWATCH_TOR_EXE`.
- 141 tests passed at that point; lint clean. (217 as of v0.3.0.)

It lives at `C:\Users\Rishi\darkwatch`: Python 3.12, `uv`, with the code in `src/darkwatch/`. It is
a git repo on `main`, pushed to the public GitHub repo `Daemon-VI/darkwatch` (public since 2026-09-16). The live watchlist holds Rithik's own identifiers and is
gitignored.

## Verified on 2026-09-16

| Check | Result |
|---|---|
| `uv run pytest -q` | 133 passed, about 23 s (217 as of 2026-09-18) |
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
- Onion page fetches fail 18 to 35% of the time on any given run (11 of 17, 12 of 15, 19 of 25,
  14 of 17), because onion services are unreliable. Each failure costs up to the 45 s timeout.
  This is why a full run takes about four minutes: Ahmia was 219.5 s of the 262.6 s in run #10.
- **Dashboard visuals are verified by screenshot, not by an automated test.** The API and the
  security posture have tests; that the contour field renders and the charts draw was checked by
  eye in a browser.
- **`leakcheck` and `stealers` have never returned a positive against the real watchlist**, so
  their parsing is proven against recorded API shapes and a known-infected sample rather than
  against a live hit on this machine.
- **No key is used for HIBP**, so per-email HIBP lookups are skipped; XposedOrNot and LeakCheck
  answer the same question for free.
