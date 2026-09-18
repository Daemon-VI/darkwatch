# Darkwatch

A dark web exposure monitor for people and companies you are authorised to protect.

You list identifiers in a watchlist: names, emails, phone numbers, domains, usernames. Darkwatch
checks them against ransomware leak sites, onion pages fetched over Tor, infostealer logs, and
breach and paste data. It scores each hit by what surrounds it, remembers what it has already
reported, and writes a report that says what to do about every hit. New hits trigger a Windows
notification, and optionally a phone push, a webhook or an email. A scheduled task runs it daily.

There is a local dashboard for everything that is easier to see than to read: keyword search
across every finding, filters, charts, triage, live scans, and one-off investigations of a value
that is not on the watchlist. `darkwatch web`, or the "Darkwatch" shortcut on the Desktop.

It only reads. It never logs in, posts, buys, or downloads files, and it keeps no page bodies.
Per finding it stores the URL, the title, the first and last time it was seen, a short snippet
around the match, and a hash of the page so a changed page can be recognised — never the page.

## What it searches

Eight sources. Seven of them need no key at all.

| Source | Needs | What it gives |
|---|---|---|
| `leaksites` | nothing | Every post that ransomware gangs have made on their leak sites, as crawled by ransomware.live (the full history since 2013, one bulk file cached for 12 hours) and RansomLook (last 30 days). Claim pages are never fetched. |
| `stealers` | nothing | Machines infected by credential-stealing malware that had a watched email, username or domain saved in the browser, via Hudson Rock's Cavalier OSINT API. This is the one source that says *your own machine*, rather than a service you used. The free tier masks the stolen values (`P********3`), which is all Darkwatch wants: enough to recognise the machine, never the credential. |
| `leakcheck` | nothing | Which breaches hold each email **or username**, and which data classes they exposed (`ssn`, `dob`, `password`, `address`). The only source that answers for a handle, so a person whose strongest identifier is a username is not invisible. |
| `xposedornot` | nothing | Breaches and pastes that included each email, plus breaches of the service at each watched domain, with the data classes exposed. The free tier allows 25 lookups per hour. |
| `hibp` | nothing / `DARKWATCH_HIBP_KEY` | Whether a watched domain's own service was breached (free). With a paid key, per-email breaches and pastes too. |
| `sites` | nothing | Which of 24 public sites carry each watched username — GitHub, X, YouTube, Mastodon, npm, Docker Hub, Hugging Face, Substack, Tumblr and more. A found profile is then read for the person's other identifiers, so a handle leads to the real name or email printed on that page. The checks run in parallel, since each site is a different host. |
| `ahmia` | Tor for pages | Ahmia's onion search index. With Tor verified, the search itself goes over Tor to Ahmia's onion service, and never over the clearnet (`ahmia_route`). Every listing is checked locally for the exact term, then matching pages are fetched over Tor as text, plus the top 5 per query. |
| `seeds` | Tor for onion URLs | Pages you choose, re-read every run, with same-host links followed one level deep. |

Every site in `sites` was verified against live responses with a handle known to exist and one
known to be free; a site that answers 200 for a free handle without a marker that proves absence
is left out, because it would report every handle as a profile. Add your own with `person_sites`.

## The dashboard

```powershell
uv run darkwatch web            # opens http://127.0.0.1:8787/?t=<token>
```

- **Search** every finding by keyword, across the term, title, URL, snippet, signals, target and
  source. Quote a phrase. Filters for severity, source, status, target and identifier type, with
  live counts.
- **Charts**: severity over the last 30 days, the mix by source, and what each run found.
- **Triage** in place — acknowledge, resolve, mark a false positive — with the recommended
  actions for each finding.
- **Run a scan** from the page and watch it happen: progress streams live over server-sent events.
- **Investigate** any value without adding it to the watchlist. Nothing is stored.
- **Export** the open findings as CSV or JSON.

It is locked down rather than merely convenient, because it serves personal data over HTTP:
it binds to loopback only, every API route requires a token minted at start-up (the link the
command prints carries it once), a non-loopback `Host` header is refused so DNS-rebinding fails,
no CORS header is ever sent, and changes are POST-only. Untrusted values — a leak-site title, an
onion page's text — are inserted as text nodes, never as HTML, and evidence URLs are shown but
never made clickable.

## Setup

This targets Windows with Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```powershell
cd C:\Users\Rishi\darkwatch
uv sync --all-extras
uv run darkwatch init          # only for a fresh checkout: writes watchlist.yaml and .env.example
```

**Tor.** Darkwatch starts `tor.exe` for each run when nothing is already listening on the
proxy port, and stops it afterwards. It finds `tor.exe` in these places, in order:

1. The `tor_exe` setting.
2. The `DARKWATCH_TOR_EXE` environment variable.
3. `PATH`.
4. `..\tools\tor-*\tor\tor.exe`.

This machine uses the Tor Expert Bundle 15.0.23 at `C:\Users\Rishi\tools\tor-15.0.23`. Its
signature was verified against the Tor Browser Developers key
`EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290`. If Tor Browser is already running, point
`tor_proxy` at `socks5h://127.0.0.1:9150` and Darkwatch will use it without starting its own.

```powershell
uv run darkwatch check-tor     # starts Tor if needed, then asks check.torproject.org
uv run darkwatch sources       # what each source searches and what limits it
```

**Secrets** live in `.env` beside the watchlist and never in the YAML. See `.env.example`:
`DARKWATCH_HIBP_KEY`, `DARKWATCH_NTFY_TOPIC`, `DARKWATCH_WEBHOOK_URL`, `DARKWATCH_SMTP_*`.

## Use

```powershell
uv run darkwatch web                        # the dashboard: search, charts, triage, live scans
uv run darkwatch run --open                 # everything; opens the HTML report at the end
uv run darkwatch run --sources leaksites    # one source
uv run darkwatch run --no-tor               # no onion page fetches
uv run darkwatch search "for sale"          # keyword search over stored findings
uv run darkwatch search --severity CRITICAL,HIGH --source leaksite
uv run darkwatch search --facets            # counts per severity, source, status, target, type
uv run darkwatch investigate jane@mail.com  # one value, live sources, nothing stored
uv run darkwatch hits                       # open hits (new and acknowledged)
uv run darkwatch hits --min-severity HIGH --snippets
uv run darkwatch show 12                    # one hit with its recommended actions
uv run darkwatch ack 12 --note "rotated password"
uv run darkwatch resolve 12
uv run darkwatch false-positive 7 --note "different person"
uv run darkwatch reopen 7
uv run darkwatch report --open              # rebuild the report from stored hits
uv run darkwatch runs                       # history: duration, documents, hits, Tor
uv run darkwatch scan-text dump.txt --save  # check a file you already hold
uv run darkwatch notify-test                # synthetic alert through every configured channel
uv run darkwatch shortcut                   # put the Desktop shortcuts in place
```

## Desktop shortcuts

`darkwatch shortcut` puts three shortcuts on your Desktop, so you never need the command line:

- **Darkwatch** starts the dashboard and opens it in your browser. This is the one to use.
- **Darkwatch - Scan now** runs a scan in a console window and opens the report when it finishes.
- **Darkwatch - Report** opens the latest report with no console window.

Remove them with `darkwatch shortcut --remove`. They point at the project's own interpreter, so
nothing has to be on `PATH`.

Reports go to `reports/` as Markdown, HTML and JSON. `latest.*` always holds the newest set,
and older sets beyond `keep_reports` (60) are deleted. The HTML report follows the system
light or dark theme and can be filtered by severity.

A hit is one identifier on one piece of evidence: a target, a term, a URL and a source. It is
reported as new once. Later runs only update its last-seen time. If a later run finds stronger
evidence at the same URL, the stored evidence is replaced and the hit keeps its triage status.
If the severity also rises, the hit is escalated: it alerts again, and a resolved hit reopens.
Reports show only targets that are still in the watchlist.

## Daily runs

```powershell
uv run darkwatch schedule install --at 09:00   # Task Scheduler: "Darkwatch daily scan"
uv run darkwatch schedule status
uv run darkwatch schedule run-now
uv run darkwatch schedule remove
```

The task runs the project's `pythonw.exe`, so no console window appears. It runs as you, only
while you are logged on, which is what lets the notification show. It keeps running on battery
and starts late if the laptop was off at the scheduled time. Output goes to
`data/logs/darkwatch.log`. A lock file stops a manual run and the scheduled run from
overlapping. It is an OS lock, so a killed run never leaves it stuck.

## Alerts

| Channel | Configure with | Receives |
|---|---|---|
| Windows notification | `notify.desktop: true` (default) | Counts and target names. Clicking it opens `latest.html`. |
| ntfy phone push | `notify.ntfy_topic` or `DARKWATCH_NTFY_TOPIC` | Severity counts only, with no names. ntfy topics are readable by anyone who knows the name. Use a long random topic, then subscribe to it in the ntfy app. |
| Webhook (Discord/Slack) | `DARKWATCH_WEBHOOK_URL` | The full summary, with identifiers and URLs. |
| Email | `DARKWATCH_SMTP_HOST`, `_PORT`, `_USER`, `_PASSWORD`, `_FROM`, `_TO`, `_STARTTLS` | The full summary. Port 465 uses implicit TLS. Certificates are verified, and Darkwatch never logs in without TLS. |

Only new or escalated hits at or above `notify.min_severity` (default MEDIUM) are sent.

## Severity

A hit's score adds up four parts:

1. **The identifier's weight:** phone 3, email 2, domain 2, name 1, username 1, keyword 1.
2. **One point per signal group.** There are six: credentials, financial, government ID, sale,
   doxxing, and access (which covers RDP, VPN, initial access and ransomware wording).
3. **The evidence's weight:** leak site 4, infostealer infection 4, onion page 2, seed page 2,
   breach 2, paste 2, Ahmia listing 1, public profile 0.
4. **Minus one point if the evidence is at least 3 years old.** The hit is then marked `dated`.

Two things are scored down rather than up, because they were the false positives that mattered:
a bare run of digits with nothing around it to say it is a phone number, and a single dictionary
word repeated as a username with no `@handle` context. Both are marked `uncorroborated` and
credited at most one point, so they surface without shouting.

| Score | Severity |
|---|---|
| Under 3 | LOW |
| 3 to 4 | MEDIUM |
| 5 to 6 | HIGH |
| 7 or more | CRITICAL |

Where signals come from depends on the evidence:

- **Onion and seed pages:** the page title plus 160 characters on either side of the match.
- **Leak-site posts:** the whole post.
- **Breaches:** the data classes the breach exposed, such as "Passwords" or "Dates of birth", rather than the prose describing it.
- **Infostealer infections:** the fact of the infection. A stealer takes saved passwords and session cookies by definition, so that is not something to look for in prose; corporate services on the same machine add the access signal.
- **Public profiles:** none. A profile a person put up is expected, so it scores LOW; the page's own wording never manufactures a breach signal. It rises only if another source finds the same identifier somewhere worse.

A plaintext combolist is also recognised structurally: two or more `user:pass` lines count as
credentials even when the page never uses the word.

Every hit lists its signals, so each score can be explained.

## Responsible use

- Monitor only identifiers you own or have written permission to monitor.
- The report tells you what to do, but it does not do it for you. Actions include changing
  passwords, turning on MFA, a SIM-swap lock, contacting the bank, reporting at
  cybercrime.gov.in or on helpline 1930, and CERT-In's 6-hour incident reporting for
  organisations in India.
- Preserve evidence with a timestamped Tor Browser screenshot before a page changes. Do not
  follow links out of a hit or download anything from an onion site. If you come across
  illegal content, stop and report it.

## Project docs

`docs/PROJECT_STATE.md` records what has been verified, with numbers.
`docs/ARCHITECTURE.md` explains how the pieces fit and why. `docs/ROADMAP.md` lists what is next.
