# Darkwatch — architecture

```
watchlist.yaml ─ config.load_watchlist ─> Watchlist(settings, targets) ─> terms (value, type, target)
                                                                             │
darkwatch run ─ RunLock ─ scanner.run_scan ──────────────────────────────────┤
                            │                                                │
                            ├─ tor.ensure_tor: port open? use it : start tor.exe, wait for 100%
                            │                  check.torproject.org must say IsTor before any onion fetch
                            │
                            ├─ sources (in order), each yields Documents(url, title, text, source,
                            │   signal_text, evidence_date):
                            │     leaksites   ransomware.live victims.json + RansomLook last/30 (FeedCache)
                            │     xposedornot breach-analytics per email (clearnet)
                            │     hibp        breaches?domain= (free); breachedaccount/pasteaccount (key)
                            │     sites       each username on GitHub/Dev.to/... (clearnet profiles)
                            │     ahmia       token → search (over Tor: onion service, then ahmia.fi)
                            │                 → local term check → onion pages over Tor
                            │     seeds       operator URLs, same-host links depth 1
                            │
                            ├─ scan_documents: Matcher.find (every occurrence) → best match per term
                            │                  per document → Store.upsert_hit (identity =
                            │                  target|term|url|source; new / escalated / seen)
                            │
                            └─ runs.info: Tor state, seconds, per-source SourceStats
                                                                             │
report.write_reports (md/html/json + latest.*, prune; current targets only)
    ─ notify.notify(new + escalated) (desktop/ntfy/webhook/email) ─ then console tables
```

## Modules (`src/darkwatch/`)

| Module | Role |
|---|---|
| `config.py` | `Term` (with a normalised `needle`), `Target`, `Settings`, `NotifySettings`, `Watchlist`. Strict YAML loading that rejects unknown keys, type coercion, `.env` loading, `find_tor_exe`, `is_onion`. |
| `tor.py` | `make_session` (requests with `socks5h`), `check_tor`, `TorProcess` (spawns tor.exe, parses `Bootstrapped N%`, times out, stops), and the `ensure_tor` context manager. |
| `fetch.py` | `fetch_text` reads text content types only, caps bytes, and enforces a per-page deadline with a watchdog. It follows redirects by hand and routes each hop. `decode_body` never raises: it takes the header charset, then `<meta>`, then UTF-8, then cp1252. `html_to_text` extracts text. |
| `cache.py` | `FeedCache`: conditional GET with ETag and Last-Modified, a max age, atomic writes, and a stale copy on network failure. |
| `matcher.py` | Per-type regexes, six signal groups, `SOURCE_WEIGHT`, the `dated` penalty, and severity bands. |
| `sources/__init__.py` | `Document` (with `signal_text`, `evidence_date`), `SourceStats`, `SourceContext` (sessions, throttle, the shared onion budget, errors), `terms_present` pre-filter, and `registry()`. |
| `sources/leaksites.py` | Tracker normalisation, the merge across the two trackers, per-post evidence URLs, and documents that carry whole-post `signal_text`. |
| `sources/xposedornot.py` | Parses breach analytics into breach and paste documents that use data-class `signal_text`. |
| `sources/hibp.py` | Domain-breach documents (keyless) and per-account documents (keyed). |
| `sources/ahmia.py` | `search_routes` (onion service, then ahmia.fi over Tor, or clearnet only without Tor), search-form token, results parser that skips Ahmia's own hosts, `plan_fetches`, bounded parallel onion fetches, and suppression of listings that fetched pages make redundant. |
| `sources/seeds.py` | Operator seed crawl. |
| `sources/sites.py` | Person footprint: `DEFAULT_SITES`, `classify` (present/absent/unknown), and profile Documents whose page text feeds the matcher the person's other identifiers. |
| `scanner.py` | `RunResult`, `scan_documents`, and `run_scan`. A source that crashes is recorded against that source and the run continues. |
| `storage.py` | SQLite `runs`, `pages` keyed on (url, source), and `hits`. Schema v3 migrations and triage statuses live here. |
| `report.py` | `actions_for(hit)` keyed by evidence, identifier and signals. Markdown, HTML and JSON renderers, `latest.*`, and pruning. |
| `notify.py` | Windows toast via PowerShell (with a notification-history read for verification), ntfy, webhook, SMTP, and redacted versus full summaries. |
| `schedule.py` | Task Scheduler XML, `schtasks` wrappers, and `RunLock` (an OS byte-range lock on `data/run.lock`). |
| `desktop.py` | Windows `.lnk` shortcuts ("Scan now", "Report") built through WScript.Shell, with a read-back for verification. |
| `cli.py`, `__main__.py` | Typer commands. `--log-file` sends all output to a file for the pythonw task. |

## Decisions and why

- **Text only, snippets only.** The fetcher refuses non-text content and caps bytes. The store
  keeps the URL, title, a text hash, and a 160-character-radius snippet. Darkwatch therefore
  cannot accumulate a copy of a leak site.
- **Leak sites come through trackers, never directly.** ransomware.live and RansomLook already
  crawl the gangs' sites, and their records hold the victim, group, dates and description.
  Fetching claim pages would touch criminal infrastructure for no extra signal. The claim URL is
  kept as evidence.
- **Leak-site data comes from a bulk file, not a per-term API.** ransomware.live's search API is
  limited to one request per minute (observed as HTTP 429 on 2026-09-16). The 21.7 MB
  `victims.json` is one conditional download per 12 hours, then matched locally in about a
  second.
- **Ahmia is searched over Tor.** A search is a list of the owner's identifiers. With Tor
  verified, the search goes to Ahmia's onion service, then to ahmia.fi through an exit, and
  never to clearnet. Both routes were tested live on 2026-09-16 and returned the same 309
  results. Ahmia's own hosts are never parsed as results: on the onion service, an empty results
  page links to itself through its time filters, and that once produced 8 false hits.
- **Ahmia is the discovery layer, but its ranking is ignored.** Ahmia filters abuse material,
  which is why it is used. Its search is a loose keyword match: an email returned 1,319
  unrelated listings, and quoting phrases changes nothing. So Darkwatch checks every listing
  for the exact term and fetches only those listings plus a bounded top-N.
- **One hit per (target, term, url, source).** The snippet was part of the key in v0.1. On a
  daily schedule, a page with a view counter would then raise a new hit every day. A stronger
  match on a later run replaces the evidence but never resets triage status.
- **Signals come from the right context.**
  - Onion pages: the title plus the match window. A page titled "Leaks" that lists
    `Canva.Com 60,390,129` is sale evidence, even though the window is just a table row.
  - Leak-site posts: the whole post, because a victim name at the start is 1,000 characters
    away from "passport scans … bank accounts".
  - Breaches: their data classes, because prose such as "was breached" says nothing about
    what was exposed.
- **A username's public footprint is a source, not an alarm.** For each `username`, the `sites`
  source checks a handful of sites that expose a profile at a predictable URL. Detection is per
  site and conservative: 404 (or a declared soft-404 marker) means the handle is free, 200 means
  it exists, and anything else (a 403 block, a login wall) is "could not tell" and skipped. A
  found profile is scored LOW and its page text is handed to the matcher, so the person's real
  name or email printed on that profile is found and recorded against it. The profile's own
  wording never manufactures a signal, so it stays LOW unless another source says worse. The
  default site list was chosen by testing live which sites give a clean 404 for a free handle;
  GitLab, npm and Reddit block non-browser requests, and PyPI and Telegram soft-404, so they are
  left out.
- **Old evidence costs a point.** Without it, a 2012 breach scored the same as a 2026 one.
  Evidence at least 3 years old is marked `dated`.
- **Tor is started per run and owned.** The `__OwningControllerProcess` option makes tor.exe exit
  if Darkwatch dies. An existing listener, such as Tor Browser, is used and left alone.
  `require_tor` refuses onion fetches unless check.torproject.org confirms a Tor exit.
- **Alerts are redacted for public channels.** An ntfy topic is readable by anyone who knows
  its name, and target names are usually searched identifiers. So ntfy gets severity counts
  only, and the desktop toast adds target names. Webhook and email get full detail. Secret URLs
  and topics are never logged. SMTP verifies certificates and refuses to log in without TLS.
- **Escalation re-alerts.** A known hit whose severity rises alerts again. A resolved hit
  reopens, but a false positive stays suppressed.
- **Fetch limits are enforced from outside the read.** A watchdog timer shuts the socket down at
  the per-page deadline, because requests' timeout is per read and a non-chunked body blocks
  until a whole chunk arrives. Redirects are followed by hand, each hop is routed by hostname,
  and 3xx bodies are never read.
- **Run exclusion is an OS lock.** A byte-range lock on `data/run.lock` is released by Windows
  when the process dies, even when it is hard-killed. A PID file could be blocked by PID reuse.
- **Untrusted text is never markup.** It is printed as Rich `Text`, escaped in HTML, and
  backslash-escaped in Markdown. The report and alerts are produced before anything is printed.
- **Scheduling uses Task Scheduler XML, not `schtasks /SC`.** The flag form cannot express
  "run on battery", "start when available", or "network required", and all three matter on a
  laptop. The task runs `pythonw.exe` with an interactive token, so there is no console window
  and the toast can still reach the desktop.
- **Configuration is strict.** Unknown settings, notify keys, target keys, and sources are
  errors. A misspelt `tor_prxy` that is silently ignored would be worse than a refusal.
- **Secrets come from the environment only.** Webhook and SMTP settings are rejected in YAML.
  The ntfy topic is allowed in YAML because the watchlist is gitignored and the topic is
  not a credential to any account.
