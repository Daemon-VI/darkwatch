"""Alerts for new hits.

Channels, and what each one is told:

| channel | configured by | content |
|---|---|---|
| desktop | `notify.desktop` (default on) | counts + target names; click opens the HTML report |
| ntfy    | `notify.ntfy_topic` or DARKWATCH_NTFY_TOPIC | counts by severity only. ntfy topics are readable by anyone who knows the name, and target names are usually searched identifiers, so no names, identifiers or URLs are sent there |
| webhook | DARKWATCH_WEBHOOK_URL | full summary (your own Discord/Slack channel) |
| email   | DARKWATCH_SMTP_* | full summary |

Only hits at or above `notify.min_severity` are alerted.
"""

from __future__ import annotations

import base64
import logging
import os
import smtplib
import ssl
import subprocess
import sys
from collections import Counter
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape, quoteattr

import requests

from .config import NotifySettings
from .matcher import SEVERITIES, severity_rank
from .storage import Hit

log = logging.getLogger(__name__)

POWERSHELL_APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"

_TOAST_PS = r"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($env:DARKWATCH_TOAST_XML)
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
$toast.Tag = $env:DARKWATCH_TOAST_TAG
$toast.Group = 'darkwatch'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:DARKWATCH_TOAST_APPID).Show($toast)
"""

_TOAST_HISTORY_PS = r"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$h = [Windows.UI.Notifications.ToastNotificationManager]::History.GetHistory($env:DARKWATCH_TOAST_APPID)
foreach ($t in $h) { if ($t.Group -eq 'darkwatch') { $t.Tag } }
"""


def severity_counts(hits: list[Hit]) -> str:
    c = Counter(h.severity for h in hits)
    return ", ".join(f"{c[s]} {s}" for s in reversed(SEVERITIES) if c[s])


def summarise(hits: list[Hit], limit: int = 10) -> str:
    """Full summary with identifiers and URLs, for private channels."""
    if not hits:
        return "Darkwatch: no new hits."
    lines = [f"Darkwatch: {len(hits)} new hit(s) ({severity_counts(hits)})."]
    for h in hits[:limit]:
        lines.append(f"- [{h.severity}] {h.target}: {h.term} ({h.term_type}) via {h.source} - {h.url}")
    if len(hits) > limit:
        lines.append(f"... and {len(hits) - limit} more; see the report.")
    return "\n".join(lines)


def summarise_redacted(hits: list[Hit], *, with_targets: bool) -> tuple[str, str]:
    """(title, body) without identifiers or URLs.

    The desktop toast may name the targets (it is on the owner's own screen). ntfy must not:
    a target name is normally also a searched identifier, and ntfy topics are readable by
    anyone who knows the topic name.
    """
    title = f"Darkwatch: {len(hits)} hit(s) need attention"
    if with_targets:
        targets = sorted({h.target for h in hits})
        body = f"{severity_counts(hits)} for {', '.join(targets)}. Open the Darkwatch report to review."
    else:
        body = f"{severity_counts(hits)}. Open the Darkwatch report on your computer to review."
    return title, body


def _where(url: str) -> str:
    """Scheme and host only: webhook URLs and ntfy topics are secrets and never go to the log."""
    p = urlparse(url)
    return f"{p.scheme}://{p.hostname or '?'}"


def filter_for_alert(hits: list[Hit], min_severity: str) -> list[Hit]:
    floor = severity_rank(min_severity)
    return [h for h in hits if severity_rank(h.severity) >= floor]


def _run_powershell(script: str, env_extra: dict[str, str], timeout: int = 30) -> subprocess.CompletedProcess:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    env = {**os.environ, **env_extra}
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-EncodedCommand", encoded],
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )


def toast_xml(title: str, body: str, open_path: str | None) -> str:
    launch = ""
    if open_path:
        uri = Path(open_path).resolve().as_uri()
        launch = f" activationType=\"protocol\" launch={quoteattr(uri)}"
    return (
        f"<toast{launch}><visual><binding template=\"ToastGeneric\">"
        f"<text>{escape(title)}</text><text>{escape(body)}</text>"
        "</binding></visual><audio src=\"ms-winsoundevent:Notification.Default\"/></toast>"
    )


def send_desktop(title: str, body: str, open_path: str | None = None, tag: str = "alert") -> bool:
    if sys.platform != "win32":
        log.info("desktop notifications are only implemented for Windows")
        return False
    try:
        r = _run_powershell(
            _TOAST_PS,
            {
                "DARKWATCH_TOAST_XML": toast_xml(title, body, open_path),
                "DARKWATCH_TOAST_TAG": tag[:16],
                "DARKWATCH_TOAST_APPID": POWERSHELL_APP_ID,
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("desktop notification failed: %s", exc)
        return False
    if r.returncode != 0:
        log.warning("desktop notification failed: %s", (r.stderr or r.stdout).strip()[:300])
        return False
    return True


def desktop_history_tags() -> list[str]:
    """Tags of Darkwatch toasts currently in the Windows notification centre (for verification)."""
    r = _run_powershell(_TOAST_HISTORY_PS, {"DARKWATCH_TOAST_APPID": POWERSHELL_APP_ID})
    return [line.strip() for line in r.stdout.splitlines() if line.strip()]


def send_ntfy(server: str, topic: str, title: str, body: str, priority: str = "default", timeout: int = 20) -> bool:
    try:
        r = requests.post(
            f"{server.rstrip('/')}/{topic}",
            data=body.encode("utf-8"),
            headers={
                "Title": title.encode("ascii", "replace").decode("ascii"),
                "Priority": priority,
                "Tags": "warning",
            },
            timeout=timeout,
        )
    except requests.RequestException as exc:
        log.warning("ntfy failed (%s): %s", _where(server), type(exc).__name__)
        return False
    if not r.ok:
        log.warning("ntfy returned HTTP %s from %s", r.status_code, _where(server))
    return r.ok


def send_webhook(url: str, text: str, timeout: int = 20) -> bool:
    try:
        r = requests.post(url, json={"content": text[:1900], "text": text[:3000]}, timeout=timeout)
    except requests.RequestException as exc:
        log.warning("webhook failed (%s): %s", _where(url), type(exc).__name__)
        return False
    if not r.ok:
        log.warning("webhook returned HTTP %s from %s", r.status_code, _where(url))
    return r.ok


def send_email(n: NotifySettings, subject: str, body: str) -> bool:
    if not (n.smtp_host and n.smtp_from and n.smtp_to):
        log.warning("email not sent: DARKWATCH_SMTP_HOST, _FROM and _TO are all required")
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = n.smtp_from
    msg["To"] = n.smtp_to
    msg.set_content(body)
    implicit_tls = n.smtp_port == 465
    if n.smtp_user and not (implicit_tls or n.smtp_starttls):
        log.warning("email not sent: refusing to send the SMTP password without TLS")
        return False
    context = ssl.create_default_context()  # verify the server certificate and host name
    try:
        if implicit_tls:
            server: smtplib.SMTP = smtplib.SMTP_SSL(n.smtp_host, n.smtp_port, timeout=30, context=context)
        else:
            server = smtplib.SMTP(n.smtp_host, n.smtp_port, timeout=30)
        with server as s:
            if n.smtp_starttls and not implicit_tls:
                s.starttls(context=context)
            if n.smtp_user:
                s.login(n.smtp_user, n.smtp_password)
            s.send_message(msg)
        return True
    except (OSError, smtplib.SMTPException, ValueError) as exc:  # ValueError: non-ASCII credentials
        log.warning("email failed (%s:%s): %s", n.smtp_host, n.smtp_port, type(exc).__name__)
        return False


def priority_for(hits: list[Hit]) -> str:
    top = max((severity_rank(h.severity) for h in hits), default=0)
    return {3: "urgent", 2: "high"}.get(top, "default")


def notify(
    n: NotifySettings, new_hits: list[Hit], *, report_path: str | None = None, tag: str = "alert"
) -> dict[str, bool | None]:
    """Send to every configured channel. Value per channel: True sent, False failed, None not configured.
    Returns {} when nothing reached the alert threshold."""
    alertable = filter_for_alert(new_hits, n.min_severity)
    if not alertable:
        return {}
    alertable.sort(key=lambda h: (-severity_rank(h.severity), -h.score))
    title, named = summarise_redacted(alertable, with_targets=True)
    _, anonymous = summarise_redacted(alertable, with_targets=False)
    full = summarise(alertable)
    out: dict[str, bool | None] = {"desktop": None, "ntfy": None, "webhook": None, "email": None}
    if n.desktop:
        out["desktop"] = send_desktop(title, named, report_path, tag=tag)
    if n.ntfy_topic:
        out["ntfy"] = send_ntfy(n.ntfy_server, n.ntfy_topic, title, anonymous, priority_for(alertable))
    if n.webhook_url:
        out["webhook"] = send_webhook(n.webhook_url, full)
    if n.smtp_host:
        out["email"] = send_email(n, title, full + (f"\n\nReport: {report_path}" if report_path else ""))
    return out
