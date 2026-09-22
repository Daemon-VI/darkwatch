# Change Log

## 0.2.0

Fixes the view and commands that did nothing, and makes installation one click.

- **Guided setup in the view.** Instead of an empty panel or a lone error row, the Findings view
  always shows the next step: *Install Darkwatch* when the CLI is missing, *Set Up Darkwatch*
  when there is no watchlist, *Open Watchlist* when it has an error, *Run First Scan* before the
  first scan, and a clear "no open findings" once a scan comes back clean.
- **Install the CLI from VS Code** (*Darkwatch: Install the CLI*), and **set up a watchlist** with
  a few questions (*Darkwatch: Set Up*).
- **Finds the CLI by itself**: on PATH, in `~/.local/bin` (where `uv tool install` puts it, even
  when VS Code was started before PATH changed), or `uv run` in an open checkout.
- **Works with no folder open**, using the watchlist in `~/Darkwatch`.
- **Commands from the Command Palette work**: Show Details, Copy URL, Acknowledge, Resolve and
  False Positive ask which finding instead of silently doing nothing.
- **Scans run without a shell**, in a terminal the extension owns: no quoting problems in
  PowerShell, values are never shell-expanded, Ctrl+C stops the whole process tree, and the view
  refreshes when a scan ends.
- New commands: Open Watchlist, Open Latest Report, Check Tor, Check the Install, Show Log.
- A CRITICAL/HIGH badge on the view; the status bar says what state Darkwatch is in.
- Hover text from untrusted pages is escaped rather than rendered as Markdown.
- Integration tests that launch VS Code and drive every state against the real CLI (`npm test`).

Needs Darkwatch CLI 0.5.0 or later (`darkwatch doctor`).

## 0.1.0

First release.

- Findings view grouped by severity, with a status-bar count.
- Run Scan, Deep Scan, and Open Dashboard in an integrated terminal.
- Search stored findings; investigate a one-off value across the live sources.
- Triage from a finding's context menu (acknowledge, resolve, false positive).
- Evidence URLs are shown and copied, never opened.
