"""Daily scan through Windows Task Scheduler, plus a single-run lock.

The task is registered from XML rather than `schtasks /SC DAILY`, because the flag form cannot
express the settings a laptop needs: keep running on battery, start late if the machine was off
at the scheduled time, and only run with a network. It runs the project's own `pythonw.exe`
(no console window) as the logged-on user, so the desktop notification can appear.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from xml.sax.saxutils import escape

TASK_NAME = "Darkwatch daily scan"


def pythonw_path() -> Path:
    exe = Path(sys.executable)
    cand = exe.with_name("pythonw.exe")
    return cand if cand.exists() else exe


def task_xml(*, time_hhmm: str, command: str, arguments: str, workdir: str, user: str) -> str:
    hh, mm = (int(x) for x in time_hhmm.split(":"))
    if not (0 <= hh < 24 and 0 <= mm < 60):
        raise ValueError("time must be HH:MM, 24-hour")
    now = datetime.now().astimezone()  # Task Scheduler boundaries are local wall-clock time
    start = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if start <= now:
        start += timedelta(days=1)
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Darkwatch: daily dark web exposure scan for the watchlist in {escape(workdir)}</Description>
    <URI>\\{escape(TASK_NAME)}</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{start.strftime("%Y-%m-%dT%H:%M:%S")}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{escape(user)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(command)}</Command>
      <Arguments>{escape(arguments)}</Arguments>
      <WorkingDirectory>{escape(workdir)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _schtasks(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["schtasks", *args], capture_output=True, text=True, errors="replace", check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def current_user() -> str:
    domain = os.environ.get("USERDOMAIN", "")
    user = os.environ.get("USERNAME", "")
    return f"{domain}\\{user}" if domain else user


def task_arguments(watchlist: Path, log_file: Path) -> str:
    return f'-m darkwatch --log-file "{log_file}" run --watchlist "{watchlist}"'


def install(watchlist: Path, time_hhmm: str, log_file: Path) -> tuple[bool, str]:
    xml = task_xml(
        time_hhmm=time_hhmm,
        command=str(pythonw_path()),
        arguments=task_arguments(watchlist, log_file),
        workdir=str(watchlist.parent),
        user=current_user(),
    )
    with tempfile.NamedTemporaryFile("wb", suffix=".xml", delete=False) as f:
        f.write(xml.encode("utf-16"))
        xml_path = f.name
    try:
        r = _schtasks("/Create", "/TN", TASK_NAME, "/XML", xml_path, "/F")
    finally:
        os.unlink(xml_path)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def remove() -> tuple[bool, str]:
    r = _schtasks("/Delete", "/TN", TASK_NAME, "/F")
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def run_now() -> tuple[bool, str]:
    r = _schtasks("/Run", "/TN", TASK_NAME)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def status() -> dict[str, str] | None:
    r = _schtasks("/Query", "/TN", TASK_NAME, "/V", "/FO", "LIST")
    if r.returncode != 0:
        return None
    wanted = {"TaskName", "Next Run Time", "Status", "Last Run Time", "Last Result",
              "Task To Run", "Scheduled Task State", "Start Time", "Power Management"}
    out: dict[str, str] = {}
    for line in r.stdout.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() in wanted and key.strip() not in out:
            out[key.strip()] = value.strip()
    return out


# ---------------------------------------------------------------------------- run lock
def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        process_query_limited_information = 0x1000
        still_active = 259
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


LOCK_OFFSET = 1 << 16  # the locked byte sits past the PID text, so the PID stays readable


class RunLock:
    """One run at a time, enforced by an OS byte-range lock on `run.lock`.

    The operating system drops the lock when the process ends for any reason (crash, Task
    Scheduler's time limit, logoff, power loss), so there is no stale-lock guesswork and no PID
    reuse problem. The file also records the holder's PID, for the "in progress" message only.
    """

    def __init__(self, path: Path):
        self.path = path
        self.held = False
        self._fd: int | None = None

    @staticmethod
    def _try_lock(fd: int) -> bool:
        os.lseek(fd, LOCK_OFFSET, os.SEEK_SET)
        try:
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, LOCK_OFFSET)
        except OSError:
            return False
        return True

    def acquire(self) -> int | None:
        """Take the lock. Returns None on success, else the holder's PID (0 if unreadable)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        if not self._try_lock(fd):
            os.close(fd)
            try:
                return int(self.path.read_text(encoding="ascii", errors="ignore")[:20].strip("\x00 \n") or 0)
            except (OSError, ValueError):
                return 0
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, f"{os.getpid()}\n".ljust(20).encode("ascii"))
        self._fd = fd
        self.held = True
        return None

    def release(self) -> None:
        if not self.held or self._fd is None:
            return
        try:
            os.lseek(self._fd, LOCK_OFFSET, os.SEEK_SET)
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        os.close(self._fd)
        self._fd = None
        self.held = False
