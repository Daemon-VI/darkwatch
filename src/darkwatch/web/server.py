"""The dashboard's HTTP layer.

It serves personal data, so it is locked down rather than merely convenient:

- It binds to the loopback address only. Nothing outside this machine can reach it.
- Every request must carry a token minted at start-up. The browser gets it once, in the URL
  the `web` command opens, and then sends it as a header. Without it another program on this
  machine (or a web page doing a cross-origin request) cannot read the data.
- The Host header must be a loopback name, which closes DNS-rebinding, and no CORS headers are
  ever sent, so a page on another origin cannot read a response even if it guesses the token.
- Mutating endpoints are POST only and also require the token, so a stray link cannot triage a
  hit by accident.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import secrets
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .. import __version__
from ..config import ALL_SOURCES, Watchlist, load_watchlist
from ..matcher import SEVERITIES
from ..report import actions_for, write_reports
from ..search import Page, as_dict, facets, investigate, search_hits, summary, timeline
from ..sources import DOC_SOURCES, registry
from ..storage import OPEN_STATUSES, STATUSES, Store
from .jobs import Job, JobManager

log = logging.getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787
STATIC = Path(__file__).parent / "static"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}
TOKEN_HEADER = "x-darkwatch-token"


@dataclass
class WebConfig:
    watchlist: Path
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    token: str = field(default_factory=lambda: secrets.token_urlsafe(24))

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/?t={self.token}"


def _csv(rows: list[dict]) -> str:
    columns = ["id", "severity", "score", "target", "term", "term_type", "source", "status",
               "first_seen", "last_seen", "title", "url", "signals", "note", "snippet"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({**row, "signals": ",".join(row.get("signals", []))})
    return buf.getvalue()


def _tuple(values: list[str] | None) -> tuple[str, ...] | None:
    return tuple(v for v in values if v) if values else None


def build_app(config: WebConfig) -> FastAPI:
    app = FastAPI(title="Darkwatch", version=__version__, docs_url=None, redoc_url=None)
    jobs = JobManager()

    def watchlist() -> Watchlist:
        """Re-read on each use, so edits to the file appear without a restart."""
        return load_watchlist(config.watchlist)

    def store() -> Store:
        return Store(watchlist().settings.db_path)

    def guard(request: Request) -> None:
        host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]")
        if host and host not in {h.strip("[]") for h in LOOPBACK_HOSTS}:
            raise HTTPException(status_code=421, detail="this server answers on localhost only")
        token = request.headers.get(TOKEN_HEADER) or request.query_params.get("t") or ""
        if not secrets.compare_digest(token, config.token):
            raise HTTPException(status_code=401, detail="bad or missing token")

    # Every /api route carries the guard as a router dependency, so no endpoint can forget it.
    api = APIRouter(prefix="/api", dependencies=[Depends(guard)])

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:  # pragma: no cover - safety net
        log.exception("unhandled error on %s", request.url.path)
        return JSONResponse({"detail": f"{type(exc).__name__}: {exc}"}, status_code=500)

    # ----------------------------------------------------------------- page and assets
    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        return HTMLResponse(html, headers={"Cache-Control": "no-store"})

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "version": __version__}

    # ----------------------------------------------------------------- reading
    @api.get("/summary")
    def api_summary() -> dict:
        wl = watchlist()
        with Store(wl.settings.db_path) as s:
            data = summary(s)
        data["version"] = __version__
        data["watchlist"] = str(wl.path)
        data["targets_configured"] = [
            {"name": t.name, "kind": t.kind, "terms": len(t.terms())} for t in wl.targets
        ]
        data["sources"] = [
            {
                "name": name,
                "enabled": name in wl.settings.sources,
                "description": src.description,
                "limitation": src.unavailable_reason(wl.settings),
            }
            for name, src in registry().items()
        ]
        data["doc_sources"] = DOC_SOURCES
        data["severities"] = list(SEVERITIES)
        data["statuses"] = list(STATUSES)
        job = jobs.current or jobs.last
        data["job"] = job.snapshot(since=max(0, len(job.events) - 1)) if job else None
        return data

    @api.get("/hits")
    def api_hits(
        q: str = "",
        severity: Annotated[list[str] | None, Query()] = None,
        source: Annotated[list[str] | None, Query()] = None,
        status: Annotated[list[str] | None, Query()] = None,
        target: Annotated[list[str] | None, Query()] = None,
        term_type: Annotated[list[str] | None, Query()] = None,
        order: str = "score",
        limit: int = 50,
        offset: int = 0,
        include_closed: bool = False,
    ) -> dict:
        statuses = _tuple(status) or (None if include_closed else OPEN_STATUSES)
        with store() as s:
            page: Page = search_hits(
                s, q, statuses=statuses, severities=_tuple(severity), sources=_tuple(source),
                targets=_tuple(target), term_types=_tuple(term_type), order=order,
                limit=limit, offset=offset,
            )
        return {
            "hits": [as_dict(h) for h in page.hits],
            "total": page.total, "took_ms": page.took_ms, "query": page.query,
            "limit": limit, "offset": offset,
        }

    @api.get("/facets")
    def api_facets(include_closed: bool = False) -> dict:
        with store() as s:
            return facets(s, None if include_closed else OPEN_STATUSES)

    @api.get("/timeline")
    def api_timeline(days: int = 30) -> dict:
        with store() as s:
            return {"days": timeline(s, days)}

    @api.get("/hits/{hit_id}")
    def api_hit(hit_id: int) -> dict:
        with store() as s:
            hit = s.get(hit_id)
        if hit is None:
            raise HTTPException(status_code=404, detail="no such hit")
        return {**as_dict(hit), "actions": actions_for(hit)}

    @api.get("/runs")
    def api_runs(limit: int = 30) -> dict:
        with store() as s:
            rows = s.runs(limit)
        out = []
        for r in rows:
            info = json.loads(r["info"] or "{}")
            out.append({
                "id": r["id"], "started": r["started"], "finished": r["finished"],
                "sources": (r["sources"] or "").split(","), "pages": r["pages"],
                "new_hits": r["new_hits"], "seen_hits": r["seen_hits"],
                "errors": [e for e in (r["errors"] or "").split("\n") if e],
                "seconds": info.get("seconds"), "tor": info.get("tor", {}),
                "source_stats": info.get("source_stats", {}),
            })
        return {"runs": out}

    @api.get("/export")
    def api_export(fmt: str = "json", include_closed: bool = False) -> Any:
        with store() as s:
            page = search_hits(s, statuses=None if include_closed else OPEN_STATUSES, limit=500)
        rows = [as_dict(h) for h in page.hits]
        if fmt == "csv":
            return StreamingResponse(
                io.StringIO(_csv(rows)), media_type="text/csv",
                headers={"Content-Disposition": 'attachment; filename="darkwatch-hits.csv"'},
            )
        return JSONResponse(rows, headers={"Content-Disposition": 'attachment; filename="darkwatch-hits.json"'})

    @api.get("/report")
    def api_report() -> Any:
        wl = watchlist()
        latest = Path(wl.settings.reports_dir) / "latest.html"
        if not latest.exists():
            raise HTTPException(status_code=404, detail="no report yet; run a scan")
        return FileResponse(latest, media_type="text/html")

    # ----------------------------------------------------------------- triage
    @api.post("/hits/status")
    def api_set_status(payload: Annotated[dict, Body()]) -> dict:
        ids = [int(i) for i in payload.get("ids", [])]
        status = str(payload.get("status", ""))
        note = str(payload.get("note", ""))
        if status not in STATUSES:
            raise HTTPException(status_code=400, detail=f"status must be one of {', '.join(STATUSES)}")
        if not ids:
            raise HTTPException(status_code=400, detail="no hit ids given")
        with store() as s:
            changed = s.set_status(ids, status, note)
        return {"changed": changed, "status": status}

    @api.post("/report/rebuild")
    def api_rebuild() -> dict:
        wl = watchlist()
        names = {t.name for t in wl.targets}
        with Store(wl.settings.db_path) as s:
            rows = [h for h in s.hits(statuses=OPEN_STATUSES) if h.target in names]
        paths = write_reports(
            rows, wl.settings.reports_dir, title="Darkwatch exposure report",
            keep=wl.settings.keep_reports,
        )
        return {"written": [str(p) for p in paths]}

    # ----------------------------------------------------------------- jobs
    def _job_response(job: Job) -> dict:
        return job.snapshot(since=0)

    @api.post("/scan")
    def api_scan(payload: Annotated[dict | None, Body()] = None) -> dict:
        payload = payload or {}
        sources = [s for s in payload.get("sources", []) if s in ALL_SOURCES] or None
        use_tor = bool(payload.get("use_tor", True))
        notify = bool(payload.get("notify", True))

        def work(job: Job) -> dict:
            from ..notify import notify as send_alerts
            from ..scanner import run_scan
            from ..schedule import RunLock

            wl = watchlist()
            lock = RunLock(Path(wl.settings.db_path).parent / "run.lock")
            holder = lock.acquire()
            if holder is not None:
                raise RuntimeError(f"another darkwatch run (pid {holder}) is in progress")
            try:
                job.emit(f"scanning {len(wl.targets)} target(s) across {', '.join(sources or wl.settings.sources)}")
                result = run_scan(wl, sources=sources, use_tor=use_tor, progress=job.emit)
                info = result.run_info()
                names = {t.name for t in wl.targets}
                with Store(wl.settings.db_path) as s:
                    open_hits = [h for h in s.hits(statuses=OPEN_STATUSES) if h.target in names]
                info["hidden_hits"] = 0
                write_reports(
                    open_hits, wl.settings.reports_dir, title="Darkwatch exposure report",
                    run_info=info, keep=wl.settings.keep_reports,
                )
                fired = {}
                if notify and result.alertable:
                    latest = Path(wl.settings.reports_dir) / "latest.html"
                    fired = send_alerts(
                        wl.settings.notify, result.alertable,
                        report_path=str(latest) if latest.exists() else None,
                        tag=f"run{result.run_id}",
                    )
                    for channel, ok in fired.items():
                        if ok is not None:
                            job.emit(f"alert {channel}: {'sent' if ok else 'FAILED'}")
                return {
                    "run_id": result.run_id, "seconds": info["seconds"], "documents": result.pages,
                    "new_hits": [as_dict(h) for h in result.new_hits],
                    "escalated_hits": [as_dict(h) for h in result.escalated_hits],
                    "seen_hits": result.seen_hits, "errors": result.errors,
                    "tor_ok": result.tor_ok, "source_stats": info.get("source_stats", {}),
                    "alerts": {k: v for k, v in fired.items() if v is not None},
                }
            finally:
                lock.release()

        try:
            job = jobs.start("scan", "full scan", work)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return _job_response(job)

    @api.post("/search")
    def api_search(payload: Annotated[dict, Body()]) -> dict:
        query = str(payload.get("query", "")).strip()
        term_type = str(payload.get("term_type", ""))
        sources = [s for s in payload.get("sources", []) if s in ALL_SOURCES] or None
        use_tor = bool(payload.get("use_tor", True))
        if not query:
            raise HTTPException(status_code=400, detail="nothing to search for")

        def work(job: Job) -> dict:
            result = investigate(
                watchlist(), query, term_type=term_type, sources=sources,
                use_tor=use_tor, progress=job.emit,
            )
            return result.as_dict()

        try:
            job = jobs.start("search", f"search {query!r}", work)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return _job_response(job)

    @api.get("/jobs/{job_id}")
    def api_job(job_id: str, since: int = 0) -> dict:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="no such job")
        return job.snapshot(since=since)

    @api.get("/jobs/{job_id}/events")
    def api_job_events(job_id: str) -> StreamingResponse:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="no such job")

        def stream():
            cursor = 0
            import time as _t

            while True:
                snap = job.snapshot(since=cursor)
                cursor = snap["cursor"]
                if snap["events"] or not snap["running"]:
                    yield f"data: {json.dumps(snap)}\n\n"
                if not snap["running"]:
                    return
                _t.sleep(0.4)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
        )

    app.include_router(api)
    return app


def serve(config: WebConfig, *, open_browser: bool = True, log_level: str = "warning") -> None:
    """Run the dashboard until interrupted."""
    import uvicorn

    app = build_app(config)
    if open_browser:
        webbrowser.open(config.url)
    uvicorn.run(app, host=config.host, port=config.port, log_level=log_level, access_log=False)
