#!/bin/sh
# Darkwatch installer for macOS and Linux:
#
#   curl -LsSf https://raw.githubusercontent.com/Daemon-VI/darkwatch/main/install.sh | sh
#
# Installs uv if it is missing, then the latest Darkwatch release as the `darkwatch` command, then
# the VS Code extension when `code` is on PATH. Run `darkwatch setup` afterwards to choose who to
# watch. Overrides: DARKWATCH_SOURCE, DARKWATCH_NO_SETUP=1, DARKWATCH_NO_VSCODE=1 (as install.ps1).
set -eu

REPO="Daemon-VI/darkwatch"
say() { printf '==> %s\n' "$1"; }

UV="$(command -v uv || true)"
[ -z "$UV" ] && [ -x "$HOME/.local/bin/uv" ] && UV="$HOME/.local/bin/uv"
if [ -z "$UV" ]; then
    say "Installing uv (Python package manager)"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    UV="$HOME/.local/bin/uv"
fi
say "Using $("$UV" --version)"

SOURCE="${DARKWATCH_SOURCE:-}"
if [ -z "$SOURCE" ]; then
    SOURCE="$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=20" 2>/dev/null \
        | grep -o '"browser_download_url": *"[^"]*darkwatch-[^"]*\.whl"' | head -n 1 \
        | sed 's/.*"\(https[^"]*\)"/\1/' || true)"
fi
[ -z "$SOURCE" ] && SOURCE="git+https://github.com/$REPO"
say "Installing Darkwatch from $SOURCE"
"$UV" tool install --force "$SOURCE"
"$UV" tool update-shell >/dev/null 2>&1 || true
DW="$("$UV" tool dir --bin)/darkwatch"
say "Installed: $("$DW" version)"

if [ -z "${DARKWATCH_NO_SETUP:-}" ] && [ -t 0 ]; then
    "$DW" setup
fi
if [ -z "${DARKWATCH_NO_VSCODE:-}" ] && command -v code >/dev/null 2>&1; then
    say "Installing the Darkwatch VS Code extension"
    code --install-extension daemon-vi.darkwatch --force || true
fi
"$DW" doctor || true
say "Done. Open a new terminal, then: darkwatch setup (if you skipped it), darkwatch run, darkwatch web"
