"""Desktop shortcuts (Windows .lnk) that launch Darkwatch without the command line.

Two shortcuts on the Desktop:
- "Darkwatch — Scan now": runs a scan in a console window, then opens the report.
- "Darkwatch — Report": opens the latest HTML report with no console window.

Both point at the project's own interpreter, so nothing has to be on PATH. The .lnk is built
through WScript.Shell, the same COM object Explorer uses, so the result is an ordinary shortcut.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

PS_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)


@dataclass
class Shortcut:
    name: str  # file name without .lnk
    target: str
    arguments: str
    workdir: str
    description: str


def _ps(script: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, timeout=timeout, check=False, creationflags=PS_FLAGS,
    )


def desktop_dir() -> Path:
    """The real Desktop, following OneDrive redirection."""
    r = _ps("[Environment]::GetFolderPath('Desktop')")
    path = r.stdout.strip()
    if r.returncode != 0 or not path:
        return Path.home() / "Desktop"
    return Path(path)


def python_for(console: bool) -> Path:
    """python.exe for a scan (so progress shows), pythonw.exe for opening the report."""
    exe = Path(sys.executable)
    if console:
        return exe.with_name("python.exe") if exe.with_name("python.exe").exists() else exe
    cand = exe.with_name("pythonw.exe")
    return cand if cand.exists() else exe


def shortcuts_for(watchlist: Path) -> list[Shortcut]:
    wl = str(watchlist)
    workdir = str(watchlist.parent)
    return [
        Shortcut(
            "Darkwatch - Scan now", str(python_for(console=True)),
            f'-m darkwatch run --open --watchlist "{wl}"', workdir,
            "Run a Darkwatch dark web exposure scan and open the report",
        ),
        Shortcut(
            "Darkwatch - Report", str(python_for(console=False)),
            f'-m darkwatch open --watchlist "{wl}"', workdir,
            "Open the latest Darkwatch exposure report",
        ),
    ]


def _lnk_script(lnk_path: Path, sc: Shortcut, icon: str) -> str:
    def q(value: str) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    return (
        "$s = (New-Object -ComObject WScript.Shell).CreateShortcut(" + q(str(lnk_path)) + ");"
        f"$s.TargetPath = {q(sc.target)};"
        f"$s.Arguments = {q(sc.arguments)};"
        f"$s.WorkingDirectory = {q(sc.workdir)};"
        f"$s.Description = {q(sc.description)};"
        f"$s.IconLocation = {q(icon)};"
        "$s.Save()"
    )


def create(sc: Shortcut, into: Path, *, icon: str = "%SystemRoot%\\System32\\imageres.dll,77") -> Path:
    into.mkdir(parents=True, exist_ok=True)
    lnk = into / f"{sc.name}.lnk"
    r = _ps(_lnk_script(lnk, sc, icon))
    if r.returncode != 0 or not lnk.exists():
        raise RuntimeError((r.stderr or r.stdout).strip() or "shortcut creation failed")
    return lnk


def read_target(lnk_path: Path) -> tuple[str, str]:
    """(TargetPath, Arguments) of an existing .lnk, for verification."""
    r = _ps(
        "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('"
        + str(lnk_path).replace("'", "''") + "'); $s.TargetPath + '|' + $s.Arguments"
    )
    target, _, args = r.stdout.strip().partition("|")
    return target, args


def install(watchlist: Path, into: Path | None = None) -> list[Path]:
    dest = into if into is not None else desktop_dir()
    return [create(sc, dest) for sc in shortcuts_for(watchlist)]


def remove(into: Path | None = None) -> list[Path]:
    dest = into if into is not None else desktop_dir()
    removed = []
    for sc in shortcuts_for(Path("x")):
        lnk = dest / f"{sc.name}.lnk"
        if lnk.exists():
            lnk.unlink()
            removed.append(lnk)
    return removed
