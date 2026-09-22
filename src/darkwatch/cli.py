"""darkwatch command line."""

from __future__ import annotations

import logging
import os
import sys
import webbrowser
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .config import (
    ALL_SOURCES,
    ENV_EXAMPLE,
    EXAMPLE_WATCHLIST,
    TERM_TYPES,
    darkwatch_home,
    find_watchlist,
    load_watchlist,
    watchlist_for,
)
from .matcher import SEVERITIES, Matcher
from .search import ORDERS
from .storage import OPEN_STATUSES, STATUSES, Hit, Store

app = typer.Typer(
    help="Darkwatch: dark web exposure monitor for people and companies you are authorised to protect.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
schedule_app = typer.Typer(help="Daily scan through Windows Task Scheduler.", no_args_is_help=True)
app.add_typer(schedule_app, name="schedule")

console = Console()
err = Console(stderr=True)

DEFAULT_WATCHLIST = Path("watchlist.yaml")
WatchlistOpt = Annotated[Path, typer.Option("--watchlist", "-w", help="Watchlist YAML file.")]
IdsArg = Annotated[list[int], typer.Argument(help="Hit ids, as shown by `darkwatch hits`.")]
NoteOpt = Annotated[str, typer.Option("--note", help="Why; stored with the hit.")]
FormatsOpt = Annotated[str, typer.Option("--formats", help="Comma-separated: md, html, json.")]
LOG_MAX_BYTES = 2_000_000
_REPLACED_STREAMS: list = []
LOG_BACKUPS = 3
SEV_STYLE = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}


def _setup_output(verbose: bool, log_file: Path | None) -> None:
    global console, err
    # pythonw (scheduled task) has no stdout at all
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure") and not stream.isatty():
            stream.reconfigure(encoding="utf-8", errors="replace")
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        # roll over at start-up only: the console and the log handler share one open file
        if log_file.exists() and log_file.stat().st_size > LOG_MAX_BYTES:
            for i in range(LOG_BACKUPS, 0, -1):
                older = log_file.with_name(f"{log_file.name}.{i}")
                newer = log_file.with_name(f"{log_file.name}.{i - 1}") if i > 1 else log_file
                if newer.exists():
                    newer.replace(older)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        handlers = [fh]
        console = Console(file=fh.stream, width=140, force_terminal=False, no_color=True)
        err = console
        # under pythonw there is no stderr: send tracebacks (typer prints them there) to the log.
        # Keep the old streams referenced; a dropped TextIOWrapper closes its buffer when collected.
        _REPLACED_STREAMS.append((sys.stdout, sys.stderr))
        sys.stdout = sys.stderr = fh.stream
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO if log_file else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
    for noisy in ("urllib3", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _progress(msg: str) -> None:
    err.print(Text(msg, style="dim"))
    logging.getLogger("darkwatch.progress").debug(msg)


def _load(watchlist: Path):
    try:
        return load_watchlist(find_watchlist(watchlist))
    except (FileNotFoundError, ValueError) as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc


def _hits_table(hits: list[Hit], title: str) -> Table:
    t = Table(title=title, show_lines=False, expand=True)
    for col, kw in (
        ("id", {"justify": "right"}), ("sev", {}), ("target", {}), ("term", {}), ("type", {}),
        ("source", {}), ("signals", {}), ("status", {}),
        # ellipsis, not fold: folding the last column in an 80-column terminal printed the URL one
        # character per line and made the table unreadable. `show <id>` prints the whole URL.
        ("title / url", {"overflow": "ellipsis", "no_wrap": True, "ratio": 3}),
    ):
        t.add_column(col, **kw)
    for h in hits:
        # every field may come from a hostile page: Text() is never parsed as Rich markup
        t.add_row(
            str(h.id), Text(h.severity, style=SEV_STYLE.get(h.severity, "")), Text(h.target), Text(h.term),
            h.term_type, h.source, ",".join(h.signals), h.status, Text(h.title or h.url),
        )
    return t


def _formats(formats: str) -> tuple[str, ...]:
    out = tuple(f.strip() for f in formats.split(",") if f.strip())
    bad = [f for f in out if f not in ("md", "html", "json")]
    if bad:
        err.print(f"[red]unknown report formats {bad}[/red]")
        raise typer.Exit(2)
    return out


@app.callback()
def _main(
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug logging.")] = False,
    log_file: Annotated[
        Path | None, typer.Option("--log-file", help="Write all output and logs to this file (used by the scheduled task).")
    ] = None,
) -> None:
    _setup_output(verbose, log_file)


@app.command()
def version() -> None:
    """Print the version."""
    console.print(f"darkwatch {__version__}")


@app.command()
def init(path: Annotated[Path, typer.Argument(help="Where to write the example watchlist.")] = DEFAULT_WATCHLIST) -> None:
    """Write an example watchlist.yaml and .env.example to start from."""
    if path.exists():
        err.print(f"[yellow]{path} already exists; not overwriting.[/yellow]")
        raise typer.Exit(1)
    path.write_text(EXAMPLE_WATCHLIST, encoding="utf-8")
    env = path.parent / ".env.example"
    if not env.exists():
        env.write_text(ENV_EXAMPLE, encoding="utf-8")
    console.print(f"Wrote {path}. Edit the targets, then run: darkwatch run")


ListOpt = Annotated[list[str] | None, typer.Option(help="Repeat, or separate with commas.")]


def _split(values: list[str] | None) -> list[str]:
    return [v.strip() for raw in values or () for v in raw.split(",") if v.strip()]


@app.command()
def setup(
    name: Annotated[str, typer.Option("--name", help="Who to watch: a person's or a company's name.")] = "",
    email: ListOpt = None,
    domain: ListOpt = None,
    username: ListOpt = None,
    phone: ListOpt = None,
    company: Annotated[bool, typer.Option("--company", help="The target is an organisation.")] = False,
    folder: Annotated[Path | None, typer.Option("--dir", help="Where to keep the watchlist, findings and reports.")] = None,
    force: Annotated[bool, typer.Option("--force", help="Replace an existing watchlist.")] = False,
    no_prompt: Annotated[bool, typer.Option("--no-prompt", help="Never ask; use only the options given.")] = False,
) -> None:
    """First-run setup: create your Darkwatch folder and a watchlist for who you protect.

    With no options it asks for a name and identifiers. The folder defaults to ~/Darkwatch
    (or DARKWATCH_HOME), and every command finds it from any directory afterwards.
    """
    folder = folder or darkwatch_home()
    path = folder / "watchlist.yaml"
    folder.mkdir(parents=True, exist_ok=True)
    env = folder / ".env.example"
    if not env.exists():
        env.write_text(ENV_EXAMPLE, encoding="utf-8")
    if path.exists() and not force:
        console.print(f"Darkwatch is already set up: {path}")
        console.print("[dim]Edit that file to change who is watched, or pass --force to start over.[/dim]")
        return
    emails, domains, usernames, phones = _split(email), _split(domain), _split(username), _split(phone)
    interactive = not no_prompt and not name and sys.stdin is not None and sys.stdin.isatty()
    if interactive:
        console.print("[bold]Darkwatch setup[/bold] — only watch people and organisations you are authorised to protect.")
        console.print("[dim]Press Enter to skip any question. Separate several values with commas.[/dim]")
        name = typer.prompt("Name of the person or company", default="", show_default=False).strip()
        if name:
            company = typer.confirm("Is this a company?", default=company)
            emails = _split([typer.prompt("Email addresses", default="", show_default=False)])
            domains = _split([typer.prompt("Domains (e.g. example.com)", default="", show_default=False)])
            usernames = _split([typer.prompt("Usernames / handles", default="", show_default=False)])
            phones = _split([typer.prompt("Phone numbers", default="", show_default=False)])
    if name:
        text = watchlist_for(name, kind="company" if company else "person", emails=emails,
                             domains=domains, usernames=usernames, phones=phones)
    else:
        text = EXAMPLE_WATCHLIST
    path.write_text(text, encoding="utf-8")
    try:
        load_watchlist(path)
    except ValueError as exc:
        path.unlink()
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(f"[green]Darkwatch is set up:[/green] {path}")
    if not name:
        console.print("[yellow]It holds example targets. Replace them with the people you protect.[/yellow]")
    console.print("Next: [bold]darkwatch run[/bold] to scan, then [bold]darkwatch web[/bold] for the dashboard.")


@app.command()
def doctor(
    watchlist: WatchlistOpt = DEFAULT_WATCHLIST,
    as_json: Annotated[bool, typer.Option("--json", help="Print the checks as JSON (for tooling, e.g. the VS Code extension).")] = False,
) -> None:
    """Check the install: the watchlist, the findings database, and Tor."""
    import json
    import platform

    from .config import Settings, find_tor_exe

    found = find_watchlist(watchlist)
    info: dict = {
        "version": __version__, "python": platform.python_version(), "executable": sys.executable,
        "home": str(darkwatch_home()), "watchlist": str(found.resolve()),
        "watchlist_exists": found.exists(), "watchlist_error": "", "targets": 0, "terms": 0,
        "db": "", "open_hits": 0, "runs": 0, "last_run": "", "tor_exe": "",
    }
    settings = Settings()
    if found.exists():
        try:
            wl = load_watchlist(found)
            settings = wl.settings
            info["targets"], info["terms"] = len(wl.targets), len(wl.terms())
        except ValueError as exc:
            info["watchlist_error"] = str(exc)
    info["tor_exe"] = settings.tor_exe or find_tor_exe("", found.resolve().parent)
    if info["targets"]:
        info["db"] = settings.db_path
        if Path(settings.db_path).exists():
            with Store(settings.db_path) as store:
                info["open_hits"] = len(store.hits(statuses=OPEN_STATUSES))
                runs = store.runs(1)
                last = store.last_run()
            info["runs"] = len(runs)
            info["last_run"] = (last["started"] or "") if last is not None else ""
    if as_json:
        print(json.dumps(info))  # raw stdout: parsed by tooling
        return
    ok, bad = "[green]ok[/green]  ", "[red]fix[/red] "
    console.print(f"darkwatch {__version__} on Python {info['python']}")
    if not info["watchlist_exists"]:
        console.print(f"{bad}no watchlist at {info['watchlist']} — run [bold]darkwatch setup[/bold]")
    elif info["watchlist_error"]:
        console.print(f"{bad}watchlist {info['watchlist']}: ", Text(info["watchlist_error"]))
    else:
        console.print(f"{ok}watchlist {info['watchlist']} ({info['targets']} target(s), {info['terms']} term(s))")
    if info["db"]:
        seen = f"{info['open_hits']} open finding(s), last run {info['last_run'][:19] or 'never'}"
        console.print(f"{ok}findings {seen}")
    if info["tor_exe"]:
        console.print(f"{ok}tor.exe {info['tor_exe']}")
    else:
        console.print(
            "[yellow]note[/yellow] tor.exe not found: onion pages are skipped, every other source works. "
            "Install Tor Browser (winget install TorProject.TorBrowser) or set DARKWATCH_TOR_EXE."
        )


@app.command("check-tor")
def check_tor_cmd(watchlist: WatchlistOpt = DEFAULT_WATCHLIST) -> None:
    """Start Tor if needed and confirm the proxy really exits through Tor."""
    from .config import Settings
    from .tor import check_tor, ensure_tor, make_session

    watchlist = find_watchlist(watchlist)
    settings = _load(watchlist).settings if watchlist.exists() else Settings()
    console.print(f"tor.exe: {settings.tor_exe or 'not found'}")
    with ensure_tor(settings, _progress) as state:
        if state["error"]:
            console.print(f"[red]Tor unavailable:[/red] {state['error']}")
            raise typer.Exit(2)
        info = check_tor(make_session(settings, via_tor=True), timeout=settings.timeout)
    how = f"started by darkwatch in {state['bootstrap_seconds']}s" if state["managed"] else "already running"
    if info["IsTor"]:
        console.print(f"[green]Tor OK[/green] via {settings.tor_proxy} ({how}); exit IP {info['IP']}")
    else:
        console.print(f"[red]Not Tor[/red] via {settings.tor_proxy}: {info['error'] or 'exit is not a Tor relay'}")
        raise typer.Exit(2)


@app.command("sources")
def sources_cmd(watchlist: WatchlistOpt = DEFAULT_WATCHLIST) -> None:
    """List the sources, whether each is enabled, and what limits it."""
    from .sources import registry

    wl = _load(watchlist)
    t = Table(title="Sources")
    for col in ("source", "enabled", "what it searches", "limitation"):
        t.add_column(col, overflow="fold")
    for name, src in registry().items():
        t.add_row(
            name, "yes" if name in wl.settings.sources else "no", src.description,
            src.unavailable_reason(wl.settings) or "-",
        )
    console.print(t)


@app.command()
def run(
    watchlist: WatchlistOpt = DEFAULT_WATCHLIST,
    sources: Annotated[str, typer.Option("--sources", "-s", help="Comma-separated subset, e.g. leaksites,ahmia.")] = "",
    no_tor: Annotated[bool, typer.Option("--no-tor", help="No Tor at all: no onion page fetches.")] = False,
    no_notify: Annotated[bool, typer.Option("--no-notify", help="Do not send alerts.")] = False,
    deep: Annotated[bool, typer.Option("--deep", help="Deep scan: every source, all Telegram channels, far more onion pages, links followed one level. Takes an hour or more.")] = False,
    formats: FormatsOpt = "md,html,json",
    open_report: Annotated[bool, typer.Option("--open", help="Open the HTML report when done.")] = False,
) -> None:
    """Search every enabled source for every watchlist term, store new hits, write a report, alert."""
    from .notify import notify
    from .report import write_reports
    from .scanner import deepen, run_scan
    from .schedule import RunLock

    wl = _load(watchlist)
    if deep:
        wl.settings = deepen(wl.settings)
        console.print(
            "[yellow]deep scan:[/yellow] every source, all Telegram channels, onion depth raised "
            "and links followed one level. This can take an hour or more; Ctrl+C to stop."
        )
    fmts = _formats(formats)
    wanted = [x.strip() for x in sources.split(",") if x.strip()] or None
    lock = RunLock(Path(wl.settings.db_path).parent / "run.lock")
    holder = lock.acquire()
    if holder is not None:
        err.print(f"[yellow]another darkwatch run (pid {holder}) is in progress; not starting.[/yellow]")
        raise typer.Exit(3)
    try:
        console.print(
            f"Scanning {len(wl.targets)} target(s), {len(wl.terms())} term(s) across "
            f"{', '.join(wanted or wl.settings.sources)}"
        )
        try:
            result = run_scan(wl, sources=wanted, use_tor=not no_tor, progress=_progress)
        except ValueError as exc:
            err.print(f"[red]{exc}[/red]")
            raise typer.Exit(2) from exc
        info = result.run_info()
        console.print(
            f"Run #{result.run_id} in {info['seconds']}s: {result.pages} document(s), "
            f"{len(result.new_hits)} new hit(s), {len(result.escalated_hits)} escalated, "
            f"{result.seen_hits} already known, "
            f"{len(result.errors)} error(s), Tor {'verified' if result.tor_ok else 'off'}"
        )
        # the report and the alerts come before any table: nothing a page contains may stop them
        with Store(wl.settings.db_path) as store:
            open_hits, hidden = _current_target_hits(store.hits(statuses=OPEN_STATUSES), wl)
        info["hidden_hits"] = hidden
        paths = write_reports(
            open_hits, wl.settings.reports_dir, title="Darkwatch exposure report",
            run_info=info, formats=fmts, keep=wl.settings.keep_reports,
        )
        for p in paths:
            console.print(f"report: {p}")
        latest_html = Path(wl.settings.reports_dir) / "latest.html"

        if not no_notify and result.alertable:
            fired = notify(
                wl.settings.notify, result.alertable,
                report_path=str(latest_html) if latest_html.exists() else None,
                tag=f"run{result.run_id}",
            )
            if not fired:
                console.print(f"alerts: no new hit reached {wl.settings.notify.min_severity}")
            for channel, ok in fired.items():
                if ok is not None:
                    console.print(f"alert {channel}: {'sent' if ok else 'FAILED'}")
        if result.new_hits:
            console.print(_hits_table(result.new_hits, "New hits"))
        if result.escalated_hits:
            console.print(_hits_table(result.escalated_hits, "Escalated hits (evidence got worse)"))
        for e in result.errors:
            err.print(Text("error: ", style="yellow") + Text(e))
        if open_report and latest_html.exists():
            webbrowser.open(latest_html.resolve().as_uri())
    finally:
        lock.release()


def _csv_opt(value: str, *, upper: bool = False) -> tuple[str, ...] | None:
    """A comma-separated option as a tuple, or None when it was not given."""
    parts = [p.strip().upper() if upper else p.strip() for p in value.split(",") if p.strip()]
    return tuple(parts) or None


def _current_target_hits(rows: list[Hit], wl) -> tuple[list[Hit], int]:
    """Hits for targets still in the watchlist, and how many were left out."""
    names = {t.name for t in wl.targets}
    kept = [h for h in rows if h.target in names]
    return kept, len(rows) - len(kept)


@app.command()
def hits(
    watchlist: WatchlistOpt = DEFAULT_WATCHLIST,
    status: Annotated[str, typer.Option("--status", help=f"One of {', '.join(STATUSES)}.")] = "",
    show_all: Annotated[bool, typer.Option("--all", help="Include resolved and false-positive hits.")] = False,
    target: Annotated[str, typer.Option("--target")] = "",
    min_severity: Annotated[str, typer.Option("--min-severity", help=f"One of {', '.join(SEVERITIES)}.")] = "",
    show_snippets: Annotated[bool, typer.Option("--snippets", help="Print each snippet.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Print the hits as JSON (for tooling, e.g. the VS Code extension).")] = False,
) -> None:
    """List stored hits (open ones by default)."""
    wl = _load(watchlist)
    if status and status not in STATUSES:
        err.print(f"[red]status must be one of {STATUSES}[/red]")
        raise typer.Exit(2)
    min_severity = min_severity.upper()
    if min_severity and min_severity not in SEVERITIES:
        err.print(f"[red]--min-severity must be one of {', '.join(SEVERITIES)}[/red]")
        raise typer.Exit(2)
    statuses = None if (status or show_all) else OPEN_STATUSES
    with Store(wl.settings.db_path) as store:
        rows = store.hits(status=status or None, statuses=statuses, target=target or None,
                          min_severity=min_severity or None)
    if as_json:
        import json as _json

        from .search import as_dict
        print(_json.dumps([as_dict(h) for h in rows]))  # raw stdout: parsed by tooling
        return
    if not rows:
        console.print("No hits match.")
        return
    console.print(_hits_table(rows, f"{len(rows)} hit(s)"))
    if show_snippets:
        for h in rows:
            console.print(Text(f"#{h.id} ", style="bold") + Text(h.snippet), "\n")


@app.command("search")
def search_cmd(
    query: Annotated[str, typer.Argument(help='Words to look for. Quote a phrase: "for sale".')] = "",
    watchlist: WatchlistOpt = DEFAULT_WATCHLIST,
    severity: Annotated[str, typer.Option("--severity", help="Comma-separated severities.")] = "",
    source: Annotated[str, typer.Option("--source", help="Comma-separated document sources.")] = "",
    target: Annotated[str, typer.Option("--target", help="Comma-separated target names.")] = "",
    term_type: Annotated[str, typer.Option("--type", help=f"Comma-separated: {', '.join(TERM_TYPES)}.")] = "",
    show_all: Annotated[bool, typer.Option("--all", help="Include resolved and false-positive hits.")] = False,
    order: Annotated[str, typer.Option("--order", help=f"One of {', '.join(ORDERS)}.")] = "score",
    limit: Annotated[int, typer.Option("--limit", "-n")] = 50,
    facets_only: Annotated[bool, typer.Option("--facets", help="Show the counts per filter instead of the hits.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Print the results as JSON (for tooling, e.g. the VS Code extension).")] = False,
) -> None:
    """Search stored findings by keyword, across every column the report shows."""
    from .search import as_dict, search_hits
    from .search import facets as facet_counts

    wl = _load(watchlist)
    if order not in ORDERS:
        err.print(f"[red]--order must be one of {', '.join(ORDERS)}[/red]")
        raise typer.Exit(2)
    statuses = None if show_all else OPEN_STATUSES
    with Store(wl.settings.db_path) as store:
        if as_json:
            import json as _json

            page = search_hits(
                store, query, statuses=statuses, severities=_csv_opt(severity, upper=True),
                sources=_csv_opt(source), targets=_csv_opt(target), term_types=_csv_opt(term_type),
                order=order, limit=limit,
            )
            print(_json.dumps({
                "hits": [as_dict(h) for h in page.hits], "total": page.total,
                "took_ms": page.took_ms, "query": page.query,
                "facets": facet_counts(store, statuses),
            }))
            return
        if facets_only:
            counts = facet_counts(store, statuses)
            for name, items in counts.items():
                if items:
                    line = "  ".join(f"{i['value']} ({i['count']})" for i in items)
                    console.print(Text(f"{name}: ", style="bold") + Text(line), highlight=False)
            return
        page = search_hits(
            store, query, statuses=statuses, severities=_csv_opt(severity, upper=True),
            sources=_csv_opt(source), targets=_csv_opt(target), term_types=_csv_opt(term_type),
            order=order, limit=limit,
        )
    if not page.hits:
        # "nothing stored" and "nothing matched your filter" are different answers
        if query:
            console.print(f"No hits match {query!r}.")
        elif any((severity, source, target, term_type)):
            console.print("No hits match those filters.")
        else:
            console.print("No hits stored yet. Run `darkwatch run` first.")
        return
    shown = f"{len(page.hits)} of {page.total}" if page.total > len(page.hits) else f"{page.total}"
    console.print(_hits_table(page.hits, f"{shown} hit(s) in {page.took_ms} ms"))


@app.command()
def investigate(
    query: Annotated[str, typer.Argument(help="An email, domain, phone, handle, name or keyword.")],
    watchlist: WatchlistOpt = DEFAULT_WATCHLIST,
    term_type: Annotated[str, typer.Option("--type", help=f"Force one of {', '.join(TERM_TYPES)}.")] = "",
    sources: Annotated[str, typer.Option("--sources", help="Comma-separated subset of sources.")] = "",
    no_tor: Annotated[bool, typer.Option("--no-tor", help="Skip onion fetches.")] = False,
    json_out: Annotated[bool, typer.Option("--json", help="Print the result as JSON.")] = False,
) -> None:
    """Search the live sources for one value without adding it to the watchlist.

    Nothing is stored: this answers "what is out there about this?" for a value you are only
    asking about once, such as an address someone just gave you.
    """
    import json as _json

    from .search import investigate as run_investigation

    wl = _load(watchlist)
    if term_type and term_type not in TERM_TYPES:
        err.print(f"[red]--type must be one of {', '.join(TERM_TYPES)}[/red]")
        raise typer.Exit(2)
    picked = list(_csv_opt(sources) or ())
    unknown = [s for s in picked if s not in ALL_SOURCES]
    if unknown:
        err.print(f"[red]unknown sources {unknown}; available: {list(ALL_SOURCES)}[/red]")
        raise typer.Exit(2)
    result = run_investigation(
        wl, query, term_type=term_type, sources=picked or None,
        use_tor=not no_tor, progress=_progress,
    )
    if json_out:
        console.print_json(_json.dumps(result.as_dict()))
        return
    console.print(
        f"[bold]{query}[/bold] read as {result.term_type}; "
        f"{result.documents} document(s) from {', '.join(result.sources)} in {result.seconds:.1f}s"
    )
    for e in result.errors:
        err.print(f"[yellow]{e}[/yellow]")
    if not result.findings:
        console.print("[green]Nothing found.[/green] That is a real negative, not a silent failure.")
        return
    table = Table(title=f"{len(result.findings)} finding(s) — not stored")
    for column in ("severity", "source", "title", "url", "signals"):
        table.add_column(column)
    for f in result.findings:
        table.add_row(
            Text(f.severity, style=SEV_STYLE.get(f.severity, "")), f.source,
            (f.title or "")[:60], f.url[:70], ", ".join(f.signals),
        )
    console.print(table)
    console.print("[dim]Add the value to your watchlist to track it over time.[/dim]")


@app.command()
def show(hit_id: Annotated[int, typer.Argument(help="Hit id.")], watchlist: WatchlistOpt = DEFAULT_WATCHLIST) -> None:
    """Everything about one hit, including the recommended actions."""
    from .report import actions_for

    wl = _load(watchlist)
    with Store(wl.settings.db_path) as store:
        h = store.get(hit_id)
    if h is None:
        err.print(f"[red]no hit #{hit_id}[/red]")
        raise typer.Exit(1)
    console.print(Text(h.severity, style=SEV_STYLE.get(h.severity, "")) + Text(
        f" #{h.id}  score {h.score}  status {h.status}"))
    for label, value in (
        ("target", h.target), ("term", f"{h.term} ({h.term_type})"), ("source", h.source),
        ("title", h.title), ("url", h.url), ("signals", ", ".join(h.signals) or "none"),
        ("first seen", h.first_seen), ("last seen", h.last_seen), ("note", h.note),
    ):
        if value:
            console.print(Text(f"{label}: ", style="bold") + Text(value), highlight=False)
    console.print(Text(f"\n{h.snippet}\n"), highlight=False)
    console.print("[bold]Recommended actions[/bold]")
    for i, a in enumerate(actions_for(h), 1):
        console.print(f"  {i}. {a}")


def _set_status(watchlist: Path, ids: list[int], status: str, note: str) -> None:
    wl = _load(watchlist)
    with Store(wl.settings.db_path) as store:
        n = store.set_status(ids, status, note)
    console.print(f"{n} hit(s) marked {status}")
    if n < len(ids):
        err.print(f"[yellow]{len(ids) - n} id(s) not found[/yellow]")


@app.command()
def ack(ids: IdsArg, watchlist: WatchlistOpt = DEFAULT_WATCHLIST, note: NoteOpt = "") -> None:
    """Mark hits as acknowledged (someone is handling them)."""
    _set_status(watchlist, ids, "acknowledged", note)


@app.command()
def resolve(ids: IdsArg, watchlist: WatchlistOpt = DEFAULT_WATCHLIST, note: NoteOpt = "") -> None:
    """Mark hits as resolved."""
    _set_status(watchlist, ids, "resolved", note)


@app.command("false-positive")
def false_positive(ids: IdsArg, watchlist: WatchlistOpt = DEFAULT_WATCHLIST, note: NoteOpt = "") -> None:
    """Mark hits as false positives; they stay stored so they are never re-reported."""
    _set_status(watchlist, ids, "false_positive", note)


@app.command()
def reopen(ids: IdsArg, watchlist: WatchlistOpt = DEFAULT_WATCHLIST, note: NoteOpt = "") -> None:
    """Set hits back to new."""
    _set_status(watchlist, ids, "new", note)


@app.command()
def report(
    watchlist: WatchlistOpt = DEFAULT_WATCHLIST,
    formats: FormatsOpt = "md,html,json",
    include_closed: Annotated[bool, typer.Option("--all", help="Include resolved and false-positive hits.")] = False,
    open_report: Annotated[bool, typer.Option("--open", help="Open the HTML report.")] = False,
) -> None:
    """Regenerate the report from stored hits without scanning."""
    import json

    from .report import write_reports

    wl = _load(watchlist)
    with Store(wl.settings.db_path) as store:
        rows, hidden = _current_target_hits(
            store.hits(statuses=None if include_closed else OPEN_STATUSES), wl
        )
        last = store.last_run()
    run_info = None
    if last is not None:
        info = json.loads(last["info"] or "{}")
        run_info = {
            "run_id": last["id"], "sources": (last["sources"] or "").split(","),
            "tor_ok": (info.get("tor") or {}).get("is_tor", False),
            "pages": last["pages"], "new_hits": last["new_hits"], "seen_hits": last["seen_hits"],
            "errors": [e for e in (last["errors"] or "").split("\n") if e],
            **info,
        }
    if run_info is not None:
        run_info["hidden_hits"] = hidden
    paths = write_reports(
        rows, wl.settings.reports_dir, title="Darkwatch exposure report", run_info=run_info,
        formats=_formats(formats), keep=wl.settings.keep_reports,
    )
    for p in paths:
        console.print(f"report: {p}")
    latest = Path(wl.settings.reports_dir) / "latest.html"
    if open_report and latest.exists():
        webbrowser.open(latest.resolve().as_uri())


@app.command()
def web(
    watchlist: WatchlistOpt = DEFAULT_WATCHLIST,
    port: Annotated[int, typer.Option("--port", "-p", help="Port on 127.0.0.1.")] = 8787,
    host: Annotated[str, typer.Option("--host", help="Bind address; loopback only.")] = "127.0.0.1",
    no_open: Annotated[bool, typer.Option("--no-open", help="Do not open a browser.")] = False,
) -> None:
    """Open the Darkwatch dashboard: search, triage, charts, scans and deep search."""
    try:
        from .web import WebConfig, serve
    except ImportError as exc:  # pragma: no cover - only when the extra is missing
        err.print(f"[red]the dashboard needs fastapi and uvicorn:[/red] uv sync --all-extras ({exc})")
        raise typer.Exit(2) from exc

    wl = _load(watchlist)
    if host not in ("127.0.0.1", "localhost", "::1"):
        err.print("[red]--host must stay on loopback: the dashboard shows personal data[/red]")
        raise typer.Exit(2)
    config = WebConfig(watchlist=wl.path, host=host, port=port)
    console.print(f"Darkwatch dashboard: {config.url}")
    console.print("[dim]That link carries a one-time token for this session. Ctrl+C to stop.[/dim]")
    try:
        serve(config, open_browser=not no_open)
    except OSError as exc:
        err.print(f"[red]could not start the dashboard on {host}:{port}:[/red] {exc}")
        raise typer.Exit(1) from exc


@app.command()
def shortcut(
    watchlist: WatchlistOpt = DEFAULT_WATCHLIST,
    remove: Annotated[bool, typer.Option("--remove", help="Delete the shortcuts instead of creating them.")] = False,
) -> None:
    """Put Darkwatch shortcuts on the Desktop (Windows): the dashboard, 'Scan now' and 'Report'."""
    from . import desktop

    if sys.platform != "win32":
        err.print("[red]desktop shortcuts are only implemented for Windows[/red]")
        raise typer.Exit(2)
    wl = _load(watchlist)
    if remove:
        gone = desktop.remove()
        console.print(f"removed {len(gone)} shortcut(s)" if gone else "no shortcuts to remove")
        return
    try:
        made = desktop.install(wl.path)
    except (OSError, RuntimeError) as exc:
        err.print(f"[red]could not create shortcuts:[/red] {exc}")
        raise typer.Exit(1) from exc
    for lnk in made:
        console.print(f"shortcut: {lnk}")
    console.print("Double-click 'Darkwatch' on your Desktop to open the dashboard.")


@app.command("open")
def open_cmd(watchlist: WatchlistOpt = DEFAULT_WATCHLIST) -> None:
    """Open the latest HTML report in the browser."""
    wl = _load(watchlist)
    latest = Path(wl.settings.reports_dir) / "latest.html"
    if not latest.exists():
        err.print("[yellow]no report yet; run `darkwatch run` first[/yellow]")
        raise typer.Exit(1)
    webbrowser.open(latest.resolve().as_uri())
    console.print(f"opened {latest}")


@app.command()
def runs(
    watchlist: WatchlistOpt = DEFAULT_WATCHLIST,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 15,
) -> None:
    """Recent runs: when, how long, what was checked, what was found."""
    import json

    wl = _load(watchlist)
    with Store(wl.settings.db_path) as store:
        rows = store.runs(limit)
    t = Table(title="Runs")
    for col in ("id", "started (UTC)", "seconds", "sources", "docs", "new", "known", "errors", "tor"):
        t.add_column(col, overflow="fold")
    for r in rows:
        info = json.loads(r["info"] or "{}")
        tor = info.get("tor") or {}
        tor_s = "verified" if tor.get("is_tor") else ("failed" if tor.get("used") else "-")
        errors = len([e for e in (r["errors"] or "").split("\n") if e])
        t.add_row(
            str(r["id"]), (r["started"] or "")[:19], str(info.get("seconds", "-") if r["finished"] else "running"),
            r["sources"], str(r["pages"]), str(r["new_hits"]), str(r["seen_hits"]), str(errors), tor_s,
        )
    console.print(t)


@app.command("scan-text")
def scan_text(
    files: Annotated[list[Path], typer.Argument(help="Text files to check.")],
    watchlist: WatchlistOpt = DEFAULT_WATCHLIST,
    save: Annotated[bool, typer.Option("--save", help="Store matches as hits (source 'file').")] = False,
) -> None:
    """Match the watchlist against local text files, such as a dump you already hold."""
    wl = _load(watchlist)
    matcher = Matcher(wl.terms())
    store = Store(wl.settings.db_path) if save else None
    run_id = store.start_run(["file"]) if store else 0
    total = new = 0
    try:
        for f in files:
            text = f.read_text(encoding="utf-8", errors="replace")
            matches = matcher.find(text, source="file", max_per_term=50)
            total += len(matches)
            console.print(f"[bold]{f}[/bold]: {len(matches)} match(es)")
            for m in matches:
                console.print(
                    f"  [{m.severity}] {m.term.target} / {m.term.value} ({m.term.type}) "
                    f"signals={','.join(m.signals) or '-'}", highlight=False,
                )
                console.print(f"    {' '.join(m.snippet.split())}", highlight=False, markup=False)
                if store:
                    up = store.upsert_hit(
                        run_id=run_id, target=m.term.target, term=m.term.value, term_type=m.term.type,
                        source="file", url=f.resolve().as_uri(), title=f.name, snippet=m.snippet,
                        signals=m.signals, score=m.score, severity=m.severity,
                    )
                    new += up.is_new
    finally:
        if store:
            store.finish_run(run_id, pages=len(files), new_hits=new, seen_hits=total - new, errors=[])
            store.close()


@app.command("notify-test")
def notify_test(watchlist: WatchlistOpt = DEFAULT_WATCHLIST) -> None:
    """Send a synthetic CRITICAL alert through every configured channel. Contains no real data."""
    from .notify import notify

    wl = _load(watchlist)
    fake = Hit(
        id=0, run_id=0, target="Darkwatch self-test", term="selftest@example.invalid", term_type="email",
        source="onion", url="http://example.invalid/", title="Darkwatch notification test",
        snippet="This is a test alert from `darkwatch notify-test`.", signals=["credentials"], score=9,
        severity="CRITICAL", first_seen="", last_seen="", status="new", note="",
    )
    latest = Path(wl.settings.reports_dir) / "latest.html"
    fired = notify(wl.settings.notify, [fake], report_path=str(latest) if latest.exists() else None, tag="selftest")
    failed = False
    for channel, ok in fired.items():
        label = "not configured" if ok is None else ("sent" if ok else "FAILED")
        console.print(f"{channel}: {label}")
        failed |= ok is False
    if failed:
        raise typer.Exit(1)


@schedule_app.command("install")
def schedule_install(
    watchlist: WatchlistOpt = DEFAULT_WATCHLIST,
    at: Annotated[str, typer.Option("--at", help="Daily start time, 24-hour HH:MM.")] = "09:00",
) -> None:
    """Register (or replace) the daily task for this watchlist."""
    from .schedule import TASK_NAME, install, pythonw_path

    wl = _load(watchlist)
    log_file = Path(wl.settings.db_path).parent / "logs" / "darkwatch.log"
    try:
        ok, out = install(wl.path, at, log_file)
    except ValueError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    if not ok:
        err.print(f"[red]could not register the task:[/red] {out}")
        raise typer.Exit(1)
    console.print(f"Registered '{TASK_NAME}': daily at {at}, runs {pythonw_path()}")
    console.print(f"log: {log_file}")


@schedule_app.command("remove")
def schedule_remove() -> None:
    """Delete the daily task."""
    from .schedule import remove

    ok, out = remove()
    console.print(out)
    if not ok:
        raise typer.Exit(1)


@schedule_app.command("status")
def schedule_status() -> None:
    """Show the task's next and last run."""
    from .schedule import TASK_NAME, status

    st = status()
    if st is None:
        console.print(f"'{TASK_NAME}' is not registered.")
        raise typer.Exit(1)
    for k, v in st.items():
        console.print(f"[bold]{k}:[/bold] {v}", highlight=False)


@schedule_app.command("run-now")
def schedule_run_now() -> None:
    """Start the scheduled task immediately (it runs in the background)."""
    from .schedule import run_now

    ok, out = run_now()
    console.print(out)
    if not ok:
        raise typer.Exit(1)


def main() -> None:
    try:
        app()
    except SystemExit:
        raise
    except BaseException:
        # the scheduled task has no console: make sure the failure is in the log file
        logging.getLogger("darkwatch").exception("darkwatch crashed")
        raise


if __name__ == "__main__":
    main()
