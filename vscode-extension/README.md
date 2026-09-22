# Darkwatch for VS Code

Run [Darkwatch](https://github.com/Daemon-VI/darkwatch) — a dark-web exposure monitor for people
and companies you are authorised to protect — without leaving the editor.

## Getting started

Open the **Darkwatch** view in the Activity Bar. It shows the next step:

1. **Install Darkwatch** — if the CLI is not installed, one click runs the official installer
   (it sets up uv and Darkwatch; no administrator rights needed).
2. **Set Up Darkwatch** — say who to watch: a name, plus any emails, domains and usernames.
3. **Run First Scan** — progress streams live in a terminal, and the view fills in when it ends.

Prefer the command line? `irm https://raw.githubusercontent.com/Daemon-VI/darkwatch/main/install.ps1 | iex`
in PowerShell does all three, and installs this extension too.

## What it does

- **Findings view**: open findings grouped by severity, with signals, a status-bar count, a
  badge for CRITICAL/HIGH, and the snippet on hover.
- **Run Scan**, **Deep Scan**, **Open Dashboard**, **Investigate a Value** — in a terminal that
  shows progress; Ctrl+C stops it.
- **Search** stored findings by keyword.
- **Triage** in place: acknowledge, resolve, or mark a false positive — from a finding's
  right-click menu, or from the Command Palette (it asks which finding).
- **Open Watchlist**, **Open Latest Report**, **Check Tor**, **Check the Install**, **Show Log**.

Evidence URLs point at leak sites and onion services, so — exactly as the Darkwatch dashboard
does — this extension never opens one for you. It shows the URL as text and copies it on request.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `darkwatch.command` | *(auto-detect)* | How to run the CLI. Empty finds `darkwatch` on PATH or in `~/.local/bin`, else `uv run darkwatch` in an open checkout. |
| `darkwatch.watchlist` | `watchlist.yaml` | Watchlist path. If it does not exist, your Darkwatch folder's watchlist (`~/Darkwatch`) is used. |
| `darkwatch.cwd` | *(workspace root)* | Working directory for the CLI. |
| `darkwatch.refreshOnStartup` | `true` | Load findings into the view when a window opens. |
| `darkwatch.openReportAfterScan` | `false` | Open the HTML report when a scan from VS Code finishes. |

## What it does not do

It never logs in, joins, pays, solves a CAPTCHA, or opens an evidence URL. It is a front end over
the same read-only CLI, run as a direct process (never through a shell); the safety posture is the CLI's.

MIT licensed. Part of the Darkwatch project.
