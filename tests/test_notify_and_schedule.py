import os
import socket
import sys
import xml.etree.ElementTree as ET

import pytest

from darkwatch import notify as nt
from darkwatch.config import NotifySettings
from darkwatch.schedule import RunLock, pid_alive, task_arguments, task_xml
from darkwatch.storage import Hit


def hit(sev="HIGH", target="Jane", term="jane@x.io", url="http://a.onion/"):
    return Hit(id=1, run_id=1, target=target, term=term, term_type="email", source="onion", url=url,
               title="t", snippet="s", signals=[], score=5, severity=sev, first_seen="", last_seen="",
               status="new", note="")


def test_summaries_and_filter():
    hits = [hit("CRITICAL"), hit("LOW", target="Acme"), hit("HIGH")]
    assert nt.severity_counts(hits) == "1 CRITICAL, 1 HIGH, 1 LOW"
    full = nt.summarise(hits, limit=2)
    assert "jane@x.io" in full and "... and 1 more" in full
    title, named = nt.summarise_redacted(hits, with_targets=True)
    _, anonymous = nt.summarise_redacted(hits, with_targets=False)
    assert title == "Darkwatch: 3 hit(s) need attention"
    assert "jane@x.io" not in named and "onion" not in named and "Acme, Jane" in named
    assert "Jane" not in anonymous and "Acme" not in anonymous and "1 CRITICAL" in anonymous
    assert [h.severity for h in nt.filter_for_alert(hits, "HIGH")] == ["CRITICAL", "HIGH"]
    assert nt.priority_for([hit("CRITICAL")]) == "urgent"
    assert nt.priority_for([hit("MEDIUM")]) == "default"


def test_toast_xml_escapes_and_links(tmp_path):
    report = tmp_path / "latest.html"
    xml = nt.toast_xml('3 hits <b>&"', "for Tom & Jerry", str(report))
    root = ET.fromstring(xml)
    assert root.get("activationType") == "protocol"
    assert root.get("launch") == report.resolve().as_uri()
    texts = [t.text for t in root.iter("text")]
    assert texts == ['3 hits <b>&"', "for Tom & Jerry"]
    assert ET.fromstring(nt.toast_xml("a", "b", None)).get("launch") is None


def test_notify_below_threshold_sends_nothing(monkeypatch):
    monkeypatch.setattr(nt, "send_desktop", lambda *a, **k: pytest.fail("should not send"))
    assert nt.notify(NotifySettings(min_severity="CRITICAL"), [hit("HIGH")]) == {}


def test_notify_routes_to_configured_channels(monkeypatch, http_server):
    http_server.add("/topic-xyz", 200, b"{}")
    http_server.add("/hook", 204, b"")
    sent_desktop = []
    monkeypatch.setattr(nt, "send_desktop", lambda title, body, path, tag="": sent_desktop.append((title, body, path, tag)) or True)
    n = NotifySettings(min_severity="HIGH", desktop=True, ntfy_topic="topic-xyz", ntfy_server=http_server.base,
                       webhook_url=http_server.base + "/hook")
    out = nt.notify(n, [hit("CRITICAL"), hit("LOW")], report_path="C:/r/latest.html", tag="run5")
    assert out == {"desktop": True, "ntfy": True, "webhook": True, "email": None}
    assert sent_desktop == [("Darkwatch: 1 hit(s) need attention",
                             "1 CRITICAL for Jane. Open the Darkwatch report to review.",
                             "C:/r/latest.html", "run5")]
    ntfy_req = next(r for r in http_server.requests if r["path"] == "/topic-xyz")
    assert ntfy_req["headers"]["Priority"] == "urgent"
    assert ntfy_req["headers"]["Title"] == "Darkwatch: 1 hit(s) need attention"
    assert b"jane@x.io" not in ntfy_req["body"] and b"Jane" not in ntfy_req["body"]
    hook_req = next(r for r in http_server.requests if r["path"] == "/hook")
    assert b"jane@x.io" in hook_req["body"]  # private channel gets the detail


def test_channel_failures_are_false_and_do_not_log_secrets(http_server, caplog):
    import logging

    caplog.set_level(logging.WARNING)
    http_server.add("/topic-secret", 500, b"no")
    assert nt.send_ntfy(http_server.base, "topic-secret", "t", "b") is False
    assert nt.send_webhook(http_server.base + "/api/webhooks/1/TOKEN", "x") is False
    assert nt.send_webhook("http://127.0.0.1:1/api/webhooks/1/TOKEN", "x") is False
    assert "TOKEN" not in caplog.text and "topic-secret" not in caplog.text
    assert nt.send_email(NotifySettings(smtp_host="h"), "s", "b") is False  # from/to missing
    no_tls = NotifySettings(smtp_host="127.0.0.1", smtp_port=1, smtp_from="a@b.c", smtp_to="d@e.f",
                            smtp_user="u", smtp_password="p", smtp_starttls=False)
    assert nt.send_email(no_tls, "s", "b") is False
    assert "without TLS" in caplog.text


def test_send_email_to_local_smtp_server():
    from aiosmtpd.controller import Controller
    from aiosmtpd.handlers import Message

    received = []

    class Handler(Message):
        def handle_message(self, message):
            received.append(message)

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    ctl = Controller(Handler(), hostname="127.0.0.1", port=port)
    ctl.start()
    try:
        n = NotifySettings(smtp_host="127.0.0.1", smtp_port=port, smtp_from="dw@example.test",
                           smtp_to="me@example.test", smtp_starttls=False)
        assert nt.send_email(n, "Darkwatch: 1 new hit(s)", "body line") is True
    finally:
        ctl.stop()
    assert len(received) == 1
    assert received[0]["Subject"] == "Darkwatch: 1 new hit(s)"
    assert received[0]["To"] == "me@example.test"
    assert "body line" in received[0].get_payload()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows toast")
def test_desktop_failure_is_reported(monkeypatch):
    class R:
        returncode = 1
        stderr = "boom"
        stdout = ""

    monkeypatch.setattr(nt, "_run_powershell", lambda *a, **k: R())
    assert nt.send_desktop("t", "b") is False


# ----------------------------------------------------------------------------- schedule
def test_task_xml_is_valid_and_laptop_friendly(tmp_path):
    xml = task_xml(time_hhmm="07:30", command=r"C:\p\pythonw.exe",
                   arguments=task_arguments(tmp_path / "w & x.yaml", tmp_path / "log.txt"),
                   workdir=str(tmp_path), user="PC\\Some User")
    root = ET.fromstring(xml.replace('encoding="UTF-16"', ""))
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    assert root.find("t:Settings/t:DisallowStartIfOnBatteries", ns).text == "false"
    assert root.find("t:Settings/t:StopIfGoingOnBatteries", ns).text == "false"
    assert root.find("t:Settings/t:StartWhenAvailable", ns).text == "true"
    assert root.find("t:Principals/t:Principal/t:LogonType", ns).text == "InteractiveToken"
    assert root.find("t:Principals/t:Principal/t:UserId", ns).text == "PC\\Some User"
    assert root.find("t:Triggers/t:CalendarTrigger/t:StartBoundary", ns).text.endswith("T07:30:00")
    args = root.find("t:Actions/t:Exec/t:Arguments", ns).text
    assert args.startswith("-m darkwatch --log-file") and "w & x.yaml" in args and " run --watchlist " in args
    with pytest.raises(ValueError):
        task_xml(time_hhmm="25:00", command="c", arguments="", workdir="w", user="u")


def test_run_lock(tmp_path):
    path = tmp_path / "run.lock"
    a = RunLock(path)
    assert a.acquire() is None and a.held
    assert path.read_text().strip() == str(os.getpid())
    b = RunLock(path)
    assert b.acquire() == os.getpid() and not b.held  # held by a: refused, holder reported
    a.release()
    a.release()  # releasing twice is harmless
    assert b.acquire() is None and b.held
    b.release()


def test_run_lock_is_released_when_the_process_dies(tmp_path):
    import subprocess
    from pathlib import Path

    path = tmp_path / "run.lock"
    code = (
        "import sys, pathlib, time; sys.path.insert(0, sys.argv[2]);"
        "from darkwatch.schedule import RunLock;"
        "l = RunLock(pathlib.Path(sys.argv[1])); assert l.acquire() is None;"
        "print('locked', flush=True); time.sleep(60)"
    )
    src = str(Path(__file__).resolve().parents[1] / "src")
    child = subprocess.Popen([sys.executable, "-c", code, str(path), src], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "locked"
        holder = RunLock(path).acquire()
        assert holder not in (None, os.getpid())  # refused; venv python.exe is a launcher, so the pid is its child
    finally:
        child.kill()  # like Task Scheduler's hard terminate: no cleanup code runs
        child.wait()
    import time

    survivor = RunLock(path)
    deadline = time.monotonic() + 10  # Windows tears the dead process (and the launcher's child) down async
    while survivor.acquire() is not None:
        assert time.monotonic() < deadline, "lock still held 10 s after the holder was killed"
        time.sleep(0.2)
    survivor.release()


def test_pid_alive():
    assert pid_alive(os.getpid())
    assert not pid_alive(0)
    assert not pid_alive(999999)
