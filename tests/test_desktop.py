import sys
from pathlib import Path

import pytest

from darkwatch import desktop


def test_shortcuts_for_targets_and_args(tmp_path):
    wl = tmp_path / "watchlist.yaml"
    scs = desktop.shortcuts_for(wl)
    assert [s.name for s in scs] == ["Darkwatch - Scan now", "Darkwatch - Report"]
    scan, report = scs
    assert scan.target.lower().endswith("python.exe")
    assert scan.arguments == f'-m darkwatch run --open --watchlist "{wl}"'
    assert report.target.lower().endswith(("pythonw.exe", "python.exe"))
    assert report.arguments == f'-m darkwatch open --watchlist "{wl}"'
    assert all(s.workdir == str(tmp_path) for s in scs)


def test_lnk_script_quotes_safely(tmp_path):
    sc = desktop.Shortcut("N", r"C:\p\python.exe", '-m darkwatch open -w "a b.yaml"', r"C:\w", "d's")
    script = desktop._lnk_script(tmp_path / "N.lnk", sc, "icon.dll,1")
    assert "WScript.Shell" in script and "$s.Save()" in script
    assert "'d''s'" in script  # the apostrophe in the description is doubled for PowerShell


@pytest.mark.skipif(sys.platform != "win32", reason="Windows shortcuts")
def test_create_and_read_shortcut(tmp_path):
    wl = tmp_path / "watchlist.yaml"
    wl.write_text("x")
    into = tmp_path / "desk"
    made = desktop.install(wl, into=into)
    assert len(made) == 2 and all(p.exists() for p in made)
    target, args = desktop.read_target(into / "Darkwatch - Scan now.lnk")
    assert target.lower().endswith("python.exe")
    assert "run --open" in args and str(wl) in args
    removed = desktop.remove(into=into)
    assert len(removed) == 2 and not any(Path(p).exists() for p in made)
