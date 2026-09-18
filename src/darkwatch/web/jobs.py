"""Background jobs (a scan, an investigation) with a live event log the dashboard can stream.

One job runs at a time. That is not a limitation to work around: a scan starts Tor, holds the
run lock and hammers the same rate-limited APIs, so a second concurrent job would only make
both slower and trip the limits. A second request is refused with the id of the running job.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

MAX_EVENTS = 2000


@dataclass
class Job:
    id: str
    kind: str  # "scan" or "search"
    label: str
    started: float = field(default_factory=time.time)
    finished: float | None = None
    events: list[dict] = field(default_factory=list)
    result: dict | None = None
    error: str | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def running(self) -> bool:
        return self.finished is None

    def emit(self, message: str, kind: str = "progress") -> None:
        with self._lock:
            if len(self.events) >= MAX_EVENTS:
                del self.events[: MAX_EVENTS // 4]
            self.events.append({"at": round(time.time() - self.started, 1), "kind": kind, "text": message})

    def snapshot(self, since: int = 0) -> dict:
        with self._lock:
            events = self.events[since:]
            return {
                "id": self.id, "kind": self.kind, "label": self.label, "running": self.running,
                "seconds": round((self.finished or time.time()) - self.started, 1),
                "events": events, "cursor": since + len(events),
                "result": self.result, "error": self.error,
            }


class JobManager:
    """Runs one job at a time in a worker thread and keeps the last one for inspection."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.current: Job | None = None
        self.last: Job | None = None

    def get(self, job_id: str) -> Job | None:
        for job in (self.current, self.last):
            if job is not None and job.id == job_id:
                return job
        return None

    def start(self, kind: str, label: str, work: Callable[[Job], dict]) -> Job:
        """Begin `work` in a thread. Raises RuntimeError when a job is already running."""
        with self._lock:
            if self.current is not None and self.current.running:
                raise RuntimeError(f"{self.current.kind} already running")
            job = Job(id=uuid.uuid4().hex[:12], kind=kind, label=label)
            self.current = job

        def run() -> None:
            try:
                job.result = work(job)
                job.emit("done", kind="done")
            except Exception as exc:
                log.exception("%s job failed", kind)
                job.error = f"{type(exc).__name__}: {exc}"
                job.emit(job.error, kind="error")
            finally:
                job.finished = time.time()
                with self._lock:
                    self.last = job
                    if self.current is job:
                        self.current = None

        threading.Thread(target=run, name=f"darkwatch-{kind}", daemon=True).start()
        return job
