# Darkwatch for VS Code

Run [Darkwatch](https://github.com/Daemon-VI/darkwatch) — a dark-web exposure monitor for people
and companies you are authorised to protect — without leaving the editor.

- **Findings view** in the Activity Bar: your stored hits grouped by severity, with signals,
  a status-bar count, and the snippet on hover.
- **Run a scan** or the **deep scan**, and **open the dashboard**, in an integrated terminal so
  you can watch Tor bootstrap and the sources run.
- **Search** stored findings by keyword, and **investigate** a one-off value across the live
  sources (nothing is stored).
- **Triage** in place: acknowledge, resolve, or mark a false positive from the finding's menu.

Evidence URLs point at leak sites and onion services, so — exactly as the Darkwatch dashboard
does — this extension never opens one for you. It shows the URL as text and copies it on request.

## Requirements

The Darkwatch CLI must be installed and runnable. Install it once:

```
uv tool install darkwatch      # then it is on your PATH as `darkwatch`
```

or point the extension at a checkout (see **darkwatch.command** below). A `watchlist.yaml`
(created by `darkwatch init`) must exist in the working directory.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `darkwatch.command` | `["darkwatch"]` | How to invoke the CLI. Use `["uv","run","darkwatch"]` to run it from a source checkout. |
| `darkwatch.watchlist` | `watchlist.yaml` | Watchlist path, relative to the working directory. |
| `darkwatch.cwd` | *(workspace root)* | Working directory for the CLI. |
| `darkwatch.refreshOnStartup` | `true` | Load findings into the view when a window opens. |

## Commands

All are under **Darkwatch:** in the Command Palette, and on the Findings view title bar.

- **Refresh Findings** · **Run Scan** · **Deep Scan (slow)** · **Open Dashboard**
- **Search Findings** · **Investigate a Value**
- On a finding: **Show Details**, **Copy Evidence URL**, **Acknowledge**, **Resolve**, **Mark False Positive**

## What it does not do

It never logs in, joins, pays, solves a CAPTCHA, or opens an evidence URL. It is a front end over
the same read-only CLI; the safety posture is the CLI's.

MIT licensed. Part of the Darkwatch project.
