# Darkwatch installer for Windows. Run in PowerShell (no administrator rights needed):
#
#   irm https://raw.githubusercontent.com/Daemon-VI/darkwatch/main/install.ps1 | iex
#
# 1. installs uv (https://docs.astral.sh/uv/) if it is missing — uv fetches a suitable Python itself;
# 2. installs the latest Darkwatch release as a command-line tool (`darkwatch`);
# 3. asks who to watch (`darkwatch setup`) and offers Desktop shortcuts;
# 4. installs the VS Code extension when VS Code is present.
#
# Environment overrides: DARKWATCH_SOURCE (a wheel path/URL or git URL to install instead of the
# latest release), DARKWATCH_NO_SETUP=1 (skip step 3), DARKWATCH_NO_VSCODE=1 (skip step 4).

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Repo = 'Daemon-VI/darkwatch'

function Say($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Warn($msg) { Write-Host "    $msg" -ForegroundColor Yellow }
# Windows PowerShell turns any stderr line from a native program into an error under 'Stop'
# (uv writes its progress there), so native programs run under 'Continue' and are judged by exit code.
function Native { $ErrorActionPreference = 'Continue'; & $args[0] @($args | Select-Object -Skip 1) }

# ---------------------------------------------------------------- uv
$uv = (Get-Command uv -ErrorAction SilentlyContinue).Source
if (-not $uv -and (Test-Path "$HOME\.local\bin\uv.exe")) { $uv = "$HOME\.local\bin\uv.exe" }
if (-not $uv) {
    Say 'Installing uv (Python package manager)'
    Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
    $uv = "$HOME\.local\bin\uv.exe"
    if (-not (Test-Path $uv)) { $uv = (Get-Command uv -ErrorAction Stop).Source }
}
Say "Using $(& $uv --version)"

# ---------------------------------------------------------------- darkwatch
$source = $env:DARKWATCH_SOURCE
if (-not $source) {
    try {
        $releases = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases?per_page=20" -Headers @{ 'User-Agent' = 'darkwatch-installer' }
        foreach ($rel in $releases) {
            if ($rel.draft -or $rel.prerelease) { continue }
            $wheel = $rel.assets | Where-Object { $_.name -like 'darkwatch-*.whl' } | Select-Object -First 1
            if ($wheel) { $source = $wheel.browser_download_url; break }
        }
    } catch { Warn "Could not read the release list ($($_.Exception.Message)); installing from the repository instead." }
}
if (-not $source) { $source = "git+https://github.com/$Repo" }
Say "Installing Darkwatch from $source"
Native $uv tool install --force $source
if ($LASTEXITCODE -ne 0) { throw "uv tool install failed (exit $LASTEXITCODE)" }
Native $uv tool update-shell 2>&1 | Out-Null
$bin = ((Native $uv tool dir --bin) | Select-Object -Last 1).ToString().Trim()
if ($env:Path -notlike "*$bin*") { $env:Path = "$bin;$env:Path" }
$dw = Join-Path $bin 'darkwatch.exe'
Say "Installed: $(& $dw version)"

# ---------------------------------------------------------------- setup
if (-not $env:DARKWATCH_NO_SETUP) {
    Say 'Setting up who to watch'
    Native $dw setup
    $answer = Read-Host 'Put Darkwatch shortcuts on the Desktop? [Y/n]'
    if ($answer -notmatch '^[nN]') { Native $dw shortcut }
}

# ---------------------------------------------------------------- VS Code
$code = (Get-Command code -ErrorAction SilentlyContinue).Source
if (-not $env:DARKWATCH_NO_VSCODE -and $code) {
    Say 'Installing the Darkwatch VS Code extension'
    Native $code --install-extension daemon-vi.darkwatch --force
    if ($LASTEXITCODE -ne 0) { Warn 'The extension did not install; get it from the Marketplace: daemon-vi.darkwatch' }
}

Write-Host ''
Native $dw doctor
Write-Host ''
Say 'Done. Open a NEW terminal, then:'
Write-Host '      darkwatch run      scan now'
Write-Host '      darkwatch web      open the dashboard'
Write-Host '      darkwatch --help   everything else'
