// Darkwatch VS Code extension.
//
// A thin, safe front end over the `darkwatch` CLI. It never opens an evidence URL in a browser —
// exactly as the dashboard does not — because those URLs point at leak sites and onion services;
// they are shown as text and copied on request only.
//
// Every CLI call is a spawn with shell:false and an argv array, including the long-running ones:
// scans, the dashboard and investigations run in a pseudoterminal this extension owns, so no value
// is ever typed into a shell, and the view refreshes itself when a scan ends.
//
// State is read through `darkwatch doctor --json` (is there a watchlist, is it valid, has a scan
// ever run) and `darkwatch hits --json`, and drives a `darkwatch.state` context key so the view
// always shows the next thing to do — install, set up, scan — instead of an empty panel.

import { ChildProcess, spawn } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";

const INSTALL_PS1 = "https://raw.githubusercontent.com/Daemon-VI/darkwatch/main/install.ps1";
const INSTALL_SH = "https://raw.githubusercontent.com/Daemon-VI/darkwatch/main/install.sh";
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV_ICON: Record<string, string> = {
  CRITICAL: "error",
  HIGH: "warning",
  MEDIUM: "info",
  LOW: "circle-outline",
};
const SEV_COLOR: Record<string, string> = {
  CRITICAL: "charts.red",
  HIGH: "charts.orange",
  MEDIUM: "charts.yellow",
  LOW: "charts.green",
};
const IS_WIN = process.platform === "win32";

export type State = "checking" | "noCli" | "noWatchlist" | "badWatchlist" | "empty" | "clean" | "ready" | "error";

interface Hit {
  id: number;
  target: string;
  term: string;
  term_type: string;
  source: string;
  url: string;
  title: string;
  snippet: string;
  signals: string[];
  score: number;
  severity: string;
  status: string;
  first_seen?: string;
  last_seen?: string;
  note?: string;
}

interface SearchPage {
  hits: Hit[];
  total: number;
  took_ms: number;
}

interface Doctor {
  version: string;
  home: string;
  watchlist: string;
  watchlist_exists: boolean;
  watchlist_error: string;
  targets: number;
  terms: number;
  open_hits: number;
  runs: number;
  last_run: string;
  tor_exe: string;
}

interface Cli {
  exe: string;
  fixed: string[];
  label: string;
}

let log: vscode.OutputChannel;
let statusBar: vscode.StatusBarItem;
let provider: HitsProvider;
let view: vscode.TreeView<vscode.TreeItem>;
let cachedCli: Cli | undefined;
let lastDoctor: Doctor | undefined;
let lastError = "";
let state: State = "checking";

function config() {
  return vscode.workspace.getConfiguration("darkwatch");
}

// --------------------------------------------------------------------------- locating the CLI

function exeNames(base: string): string[] {
  return IS_WIN ? [`${base}.exe`, `${base}.cmd`, base] : [base];
}

/** An executable by name on PATH, or undefined. */
function onPath(base: string): string | undefined {
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
    for (const name of exeNames(base)) {
      const full = path.join(dir, name);
      if (dir && fs.existsSync(full) && fs.statSync(full).isFile()) {
        return full;
      }
    }
  }
  return undefined;
}

/** Where `uv tool install` puts executables, which a VS Code started earlier may not have on PATH. */
function toolBinDirs(): string[] {
  const dirs = [process.env.UV_TOOL_BIN_DIR, process.env.XDG_BIN_HOME, path.join(os.homedir(), ".local", "bin")];
  return dirs.filter((d): d is string => !!d);
}

function findExe(base: string): string | undefined {
  const hit = onPath(base);
  if (hit) {
    return hit;
  }
  for (const dir of toolBinDirs()) {
    for (const name of exeNames(base)) {
      const full = path.join(dir, name);
      if (fs.existsSync(full)) {
        return full;
      }
    }
  }
  return undefined;
}

/** A workspace folder that is a Darkwatch source checkout, run through `uv run`. */
function checkoutFolder(): string | undefined {
  for (const f of vscode.workspace.workspaceFolders ?? []) {
    const pyproject = path.join(f.uri.fsPath, "pyproject.toml");
    try {
      if (/^name\s*=\s*"darkwatch"/m.test(fs.readFileSync(pyproject, "utf-8"))) {
        return f.uri.fsPath;
      }
    } catch {
      // not a checkout
    }
  }
  return undefined;
}

function candidates(): Cli[] {
  const configured = config().get<string[]>("command") ?? [];
  if (configured.length && configured[0]) {
    const [exe, ...fixed] = configured;
    // a bare name is resolved the same way as the auto-detected one, so ["uv", ...] and
    // ["darkwatch"] work even when VS Code's PATH is older than the install
    const resolved = path.isAbsolute(exe) ? exe : findExe(exe) ?? exe;
    return [{ exe: resolved, fixed, label: configured.join(" ") }];
  }
  const out: Cli[] = [];
  const installed = findExe("darkwatch");
  if (installed) {
    out.push({ exe: installed, fixed: [], label: installed });
  }
  const uv = findExe("uv");
  if (uv && checkoutFolder()) {
    out.push({ exe: uv, fixed: ["run", "--project", checkoutFolder()!, "darkwatch"], label: "uv run darkwatch" });
  }
  return out;
}

/** The first candidate that answers `darkwatch version`. Cached until reset. */
async function resolveCli(): Promise<Cli | undefined> {
  if (cachedCli) {
    return cachedCli;
  }
  for (const cli of candidates()) {
    try {
      const out = await exec(cli, ["version"], os.homedir(), 120_000);
      log.appendLine(`using ${cli.label}: ${out.trim()}`);
      cachedCli = cli;
      return cli;
    } catch (e) {
      log.appendLine(`not usable: ${cli.label}: ${(e as Error).message}`);
    }
  }
  return undefined;
}

// --------------------------------------------------------------------------- running the CLI

/** The working directory: the setting, else the first workspace folder, else the home folder. */
function workdir(): string {
  const cwd = config().get<string>("cwd")?.trim();
  if (cwd) {
    return cwd;
  }
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? os.homedir();
}

/**
 * `--watchlist` for every data command. A path in the setting that exists (absolute, or
 * relative to the working directory) is passed; otherwise nothing is, and the CLI falls back to
 * the watchlist in the Darkwatch home folder that `darkwatch setup` created.
 */
function watchlistArgs(): string[] {
  const setting = config().get<string>("watchlist")?.trim() || "watchlist.yaml";
  const full = path.isAbsolute(setting) ? setting : path.join(workdir(), setting);
  if (fs.existsSync(full) || path.isAbsolute(setting)) {
    return ["--watchlist", full];
  }
  return [];
}

function cliEnv(): NodeJS.ProcessEnv {
  return { ...process.env, PYTHONIOENCODING: "utf-8", PYTHONUTF8: "1", PYTHONUNBUFFERED: "1" };
}

/** Run the CLI to completion and return stdout. Rejects with a readable message on failure. */
function exec(cli: Cli, args: string[], cwd = workdir(), timeoutMs = 300_000): Promise<string> {
  return new Promise((resolve, reject) => {
    // shell:false and an argv array: search and investigate values are never shell-interpreted
    const child = spawn(cli.exe, [...cli.fixed, ...args], { cwd, shell: false, env: cliEnv(), windowsHide: true });
    let out = "";
    let err = "";
    const timer = setTimeout(() => {
      killTree(child);
      reject(new Error(`darkwatch ${args[0]} took longer than ${timeoutMs / 1000}s`));
    }, timeoutMs);
    child.stdout.on("data", (d: Buffer) => (out += d.toString("utf-8")));
    child.stderr.on("data", (d: Buffer) => (err += d.toString("utf-8")));
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(new Error(`could not start '${cli.exe}': ${e.message}`));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) {
        resolve(out);
      } else {
        reject(new Error(err.trim() || out.trim() || `darkwatch exited with code ${code}`));
      }
    });
  });
}

async function runCli(args: string[]): Promise<string> {
  const cli = await resolveCli();
  if (!cli) {
    throw new Error("the Darkwatch CLI is not installed. Run 'Darkwatch: Install the CLI'.");
  }
  log.appendLine(`$ darkwatch ${args.join(" ")}`);
  return exec(cli, args);
}

function killTree(child: ChildProcess | undefined): void {
  if (!child || child.exitCode !== null || child.pid === undefined) {
    return;
  }
  if (IS_WIN) {
    // the darkwatch.exe / uv launchers start python as a child: end the whole tree
    spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], { windowsHide: true });
  } else {
    child.kill("SIGINT");
  }
}

/**
 * Run a process in a terminal this extension owns. Output streams live (Tor bootstrap, sources
 * finishing), Ctrl+C stops it, and `onExit` runs when it ends.
 */
function runInTerminal(name: string, exe: string, args: string[], cwd: string, onExit?: (code: number) => void,
  extraEnv: NodeJS.ProcessEnv = {}): vscode.Terminal {
  const write = new vscode.EventEmitter<string>();
  const close = new vscode.EventEmitter<number | void>();
  const decoder = new TextDecoder("utf-8");
  let child: ChildProcess | undefined;
  let finished = false;
  const emit = (b: Buffer) => write.fire(decoder.decode(b, { stream: true }).replace(/\r?\n/g, "\r\n"));
  const pty: vscode.Pseudoterminal = {
    onDidWrite: write.event,
    onDidClose: close.event,
    open: () => {
      write.fire(`\x1b[2m> ${[path.basename(exe), ...args].join(" ")}\x1b[0m\r\n`);
      child = spawn(exe, args, {
        cwd, shell: false, windowsHide: true,
        env: { ...cliEnv(), FORCE_COLOR: "1", COLUMNS: "120", ...extraEnv },
      });
      child.stdout?.on("data", emit);
      child.stderr?.on("data", emit);
      child.on("error", (e) => {
        write.fire(`\r\n\x1b[31mcould not start ${exe}: ${e.message}\x1b[0m\r\n`);
      });
      child.on("close", (code) => {
        finished = true;
        const colour = code === 0 ? "32" : "33";
        write.fire(`\r\n\x1b[${colour}m[finished with code ${code ?? "?"}] Press any key to close.\x1b[0m\r\n`);
        onExit?.(code ?? -1);
      });
    },
    close: () => killTree(child),
    handleInput: (data) => {
      if (finished) {
        close.fire();
      } else if (data === "\x03") {
        write.fire("^C\r\n");
        killTree(child);
      } else if (child?.stdin?.writable) {
        const text = data.replace(/\r/g, "\n");
        write.fire(data.replace(/\r/g, "\r\n"));
        child.stdin.write(text);
      }
    },
  };
  const term = vscode.window.createTerminal({ name, pty, iconPath: new vscode.ThemeIcon("shield") });
  term.show();
  return term;
}

/** A CLI command in a terminal; refreshes the view when it ends. */
async function runCliInTerminal(name: string, args: string[], refreshAfter = true): Promise<void> {
  const cli = await resolveCli();
  if (!cli) {
    await offerInstall();
    return;
  }
  runInTerminal(name, cli.exe, [...cli.fixed, ...args], workdir(), () => {
    if (refreshAfter) {
      void provider.refresh();
    }
  });
}

// --------------------------------------------------------------------------- tree

class SeverityGroup extends vscode.TreeItem {
  constructor(public readonly severity: string, public readonly hits: Hit[]) {
    super(`${severity} (${hits.length})`, vscode.TreeItemCollapsibleState.Expanded);
    this.iconPath = new vscode.ThemeIcon(SEV_ICON[severity] ?? "circle-outline", new vscode.ThemeColor(SEV_COLOR[severity] ?? "foreground"));
    this.contextValue = "severity";
  }
}

class HitItem extends vscode.TreeItem {
  constructor(public readonly hit: Hit) {
    super(`${hit.term}`, vscode.TreeItemCollapsibleState.None);
    this.description = `${hit.source}${hit.signals.length ? "  ·  " + hit.signals.join(", ") : ""}`;
    // untrusted text (a leak-site title, an onion page's words) is escaped, never rendered as markdown
    const md = new vscode.MarkdownString();
    md.appendMarkdown(`**${hit.severity}** · score ${hit.score} · ${hit.status}\n\n`);
    md.appendText(`${hit.term} (${hit.term_type}) — ${hit.target}`);
    if (hit.title) {
      md.appendMarkdown("\n\n");
      md.appendText(hit.title);
    }
    if (hit.snippet) {
      md.appendMarkdown("\n\n");
      md.appendText(hit.snippet);
    }
    md.appendMarkdown("\n\n*The evidence URL is shown in the details; it is never opened for you.*");
    this.tooltip = md;
    this.iconPath = new vscode.ThemeIcon(SEV_ICON[hit.severity] ?? "circle-outline", new vscode.ThemeColor(SEV_COLOR[hit.severity] ?? "foreground"));
    this.contextValue = "hit";
    this.command = { command: "darkwatch.showHit", title: "Show Finding Details", arguments: [this] };
  }
}

class HitsProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.changed.event;
  hits: Hit[] = [];
  private groups: SeverityGroup[] = [];
  private running: Promise<void> | undefined;
  lastRefresh = 0;

  getTreeItem(e: vscode.TreeItem): vscode.TreeItem {
    return e;
  }

  getChildren(element?: vscode.TreeItem): vscode.TreeItem[] {
    if (!element) {
      // empty unless there are findings, so the welcome view for the current state shows
      return state === "ready" ? this.groups : [];
    }
    if (element instanceof SeverityGroup) {
      return element.hits.map((h) => new HitItem(h));
    }
    return [];
  }

  refresh(): Promise<void> {
    // one refresh at a time; a request during a refresh joins it
    this.running ??= this.load().finally(() => (this.running = undefined));
    return this.running;
  }

  private async load(): Promise<void> {
    this.lastRefresh = Date.now();
    await setState("checking");
    this.hits = [];
    try {
      const cli = await resolveCli();
      if (!cli) {
        await setState("noCli");
        return;
      }
      const doctor = JSON.parse(await runCli(["doctor", ...watchlistArgs(), "--json"])) as Doctor;
      lastDoctor = doctor;
      if (!doctor.watchlist_exists) {
        await setState("noWatchlist");
        return;
      }
      if (doctor.watchlist_error) {
        lastError = doctor.watchlist_error;
        await setState("badWatchlist");
        return;
      }
      this.hits = JSON.parse((await runCli(["hits", ...watchlistArgs(), "--json"])) || "[]") as Hit[];
      this.groups = SEVERITIES.map((sev) => new SeverityGroup(sev, this.hits.filter((h) => h.severity === sev)))
        .filter((g) => g.hits.length > 0);
      await setState(this.hits.length ? "ready" : doctor.runs ? "clean" : "empty");
    } catch (e) {
      lastError = (e as Error).message;
      log.appendLine(`error: ${lastError}`);
      await setState("error");
    }
  }

  fire(): void {
    this.changed.fire();
  }
}

async function setState(next: State): Promise<void> {
  state = next;
  await vscode.commands.executeCommand("setContext", "darkwatch.state", next);
  const high = provider.hits.filter((h) => h.severity === "CRITICAL" || h.severity === "HIGH").length;
  const d = lastDoctor;
  const watching = d ? `${d.targets} target(s), ${d.terms} term(s)` : "";
  const last = d?.last_run ? `last scan ${d.last_run.slice(0, 16).replace("T", " ")} UTC` : "never scanned";
  const status: Record<State, [string, string]> = {
    checking: ["$(sync~spin) Darkwatch", "Checking Darkwatch…"],
    noCli: ["$(shield) Darkwatch: install", "The Darkwatch CLI is not installed. Click to set it up."],
    noWatchlist: ["$(shield) Darkwatch: set up", "No watchlist yet. Click to set up who to watch."],
    badWatchlist: ["$(shield) Darkwatch: fix watchlist", `The watchlist has a problem: ${lastError}`],
    empty: ["$(shield) Darkwatch", `Watching ${watching}; no scan has run yet.`],
    clean: ["$(shield) Darkwatch: 0", `No open findings. Watching ${watching}; ${last}.`],
    ready: [`$(shield) Darkwatch: ${provider.hits.length}`,
      `${provider.hits.length} open finding(s)${high ? `, ${high} CRITICAL/HIGH` : ""}. ${last}.`],
    error: ["$(shield) Darkwatch: error", lastError],
  };
  [statusBar.text, statusBar.tooltip] = status[next];
  statusBar.backgroundColor = next === "ready" && high ? new vscode.ThemeColor("statusBarItem.warningBackground")
    : next === "error" || next === "badWatchlist" ? new vscode.ThemeColor("statusBarItem.errorBackground") : undefined;
  view.message = next === "ready" || next === "clean" || next === "empty"
    ? `Watching ${watching} · ${last}`
    : next === "badWatchlist" || next === "error" ? lastError : undefined;
  view.badge = next === "ready" && high ? { value: high, tooltip: `${high} CRITICAL/HIGH finding(s)` } : undefined;
  provider.fire();
}

// --------------------------------------------------------------------------- install & setup

async function offerInstall(): Promise<void> {
  const pick = await vscode.window.showWarningMessage(
    "The Darkwatch CLI is not installed (or not found). Install it now? It takes a minute.",
    "Install", "Settings",
  );
  if (pick === "Install") {
    await installCli();
  } else if (pick === "Settings") {
    await vscode.commands.executeCommand("workbench.action.openSettings", "darkwatch.command");
  }
}

async function installCli(): Promise<void> {
  const script = IS_WIN ? INSTALL_PS1 : INSTALL_SH;
  const go = await vscode.window.showInformationMessage(
    "Install the Darkwatch CLI?",
    {
      modal: true,
      detail: `This runs the official installer from the Darkwatch repository (${script}). It installs uv ` +
        "if it is missing, then Darkwatch itself with `uv tool install`. Nothing needs administrator rights.",
    },
    "Install",
  );
  if (go !== "Install") {
    return;
  }
  const [exe, args] = IS_WIN
    ? ["powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", `irm ${script} | iex`]]
    : ["sh", ["-c", `curl -LsSf ${script} | sh`]];
  // the extension does its own setup and is already installed: the installer skips both
  runInTerminal("Darkwatch: install", exe, args as string[], os.homedir(), (code) => {
    cachedCli = undefined;
    void provider.refresh().then(() => {
      if (code === 0 && state === "noWatchlist") {
        void setup();
      }
    });
  }, { DARKWATCH_NO_SETUP: "1", DARKWATCH_NO_VSCODE: "1" });
}

function splitList(value: string | undefined): string[] {
  return (value ?? "").split(",").map((v) => v.trim()).filter(Boolean);
}

async function setup(): Promise<void> {
  const cli = await resolveCli();
  if (!cli) {
    await offerInstall();
    return;
  }
  const title = "Darkwatch setup";
  const name = await vscode.window.showInputBox({
    title, prompt: "Who do you want to watch? Only people and organisations you are authorised to protect.",
    placeHolder: "a person's or company's name (leave empty for an example watchlist)", ignoreFocusOut: true,
  });
  if (name === undefined) {
    return;
  }
  const args = ["setup", "--no-prompt"];
  if (name.trim()) {
    const kind = await vscode.window.showQuickPick(["Person", "Company"], { title, placeHolder: `Is ${name} a person or a company?`, ignoreFocusOut: true });
    if (!kind) {
      return;
    }
    const ask = (prompt: string, placeHolder: string) =>
      vscode.window.showInputBox({ title, prompt, placeHolder, ignoreFocusOut: true });
    const emails = await ask("Email addresses (optional, comma-separated)", "name@example.com, other@example.org");
    if (emails === undefined) { return; }
    const domains = await ask("Domains (optional)", "example.com");
    if (domains === undefined) { return; }
    const usernames = await ask("Usernames or handles (optional)", "handle123");
    if (usernames === undefined) { return; }
    args.push("--name", name.trim());
    if (kind === "Company") {
      args.push("--company");
    }
    for (const [flag, values] of [["--email", emails], ["--domain", domains], ["--username", usernames]] as const) {
      for (const v of splitList(values)) {
        args.push(flag, v);
      }
    }
  }
  try {
    const out = await runCli(args);
    log.appendLine(out);
    await provider.refresh();
    if (lastDoctor?.watchlist_exists) {
      await openFile(lastDoctor.watchlist);
    }
    const next = await vscode.window.showInformationMessage(
      name.trim() ? "Darkwatch is set up. Run the first scan now?" : "Darkwatch wrote an example watchlist. Replace the example targets, then run a scan.",
      "Run scan",
    );
    if (next === "Run scan") {
      await vscode.commands.executeCommand("darkwatch.runScan");
    }
  } catch (e) {
    vscode.window.showErrorMessage(`Darkwatch setup: ${(e as Error).message}`);
  }
}

async function openFile(file: string): Promise<void> {
  const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(file));
  await vscode.window.showTextDocument(doc, { preview: false });
}

async function openWatchlist(): Promise<void> {
  if (!lastDoctor) {
    await provider.refresh();
  }
  if (lastDoctor?.watchlist_exists) {
    await openFile(lastDoctor.watchlist);
  } else if (state === "noCli") {
    await offerInstall();
  } else {
    await setup();
  }
}

// --------------------------------------------------------------------------- details & triage

/** The finding a command acts on: the tree item it was run on, else a pick from the open ones. */
async function hitFor(item: HitItem | undefined, verb: string): Promise<Hit | undefined> {
  if (item?.hit) {
    return item.hit;
  }
  if (!provider.hits.length) {
    await provider.refresh();
  }
  if (!provider.hits.length) {
    vscode.window.showInformationMessage("Darkwatch has no open findings.");
    return undefined;
  }
  const pick = await vscode.window.showQuickPick(
    provider.hits.map((h) => ({
      label: `$(${SEV_ICON[h.severity] ?? "circle-outline"}) #${h.id} ${h.term}`,
      description: `${h.severity} · ${h.source}`,
      detail: h.title || h.url,
      hit: h,
    })),
    { title: `Finding to ${verb}`, matchOnDescription: true, matchOnDetail: true },
  );
  return pick?.hit;
}

async function showHit(item?: HitItem): Promise<void> {
  const hit = await hitFor(item, "show");
  if (!hit) {
    return;
  }
  const lines = [
    `Darkwatch finding #${hit.id}`,
    "=".repeat(40),
    `severity : ${hit.severity}   score ${hit.score}   status ${hit.status}`,
    `target   : ${hit.target}`,
    `term     : ${hit.term}  (${hit.term_type})`,
    `source   : ${hit.source}`,
    `signals  : ${hit.signals.join(", ") || "none"}`,
    `first    : ${hit.first_seen ?? "?"}`,
    `last     : ${hit.last_seen ?? "?"}`,
    hit.note ? `note     : ${hit.note}` : "",
    "",
    `title    : ${hit.title || "(none)"}`,
    `url      : ${hit.url}`,
    "           ^ evidence URL — copy it if you need it; it is deliberately not opened for you,",
    "             because it points at a leak site or onion service.",
    "",
    "snippet:",
    hit.snippet || "(none)",
  ].filter((l, i, all) => l !== "" || all[i - 1] !== "");
  const doc = await vscode.workspace.openTextDocument({ content: lines.join("\n"), language: "plaintext" });
  await vscode.window.showTextDocument(doc, { preview: true });
}

async function copyUrl(item?: HitItem): Promise<void> {
  const hit = await hitFor(item, "copy the evidence URL of");
  if (!hit) {
    return;
  }
  await vscode.env.clipboard.writeText(hit.url);
  vscode.window.showInformationMessage("Evidence URL copied to the clipboard.");
}

async function triage(item: HitItem | undefined, verb: string, label: string): Promise<void> {
  const hit = await hitFor(item, `mark ${label}`);
  if (!hit) {
    return;
  }
  let note = "";
  if (verb === "false-positive" || verb === "resolve") {
    const typed = await vscode.window.showInputBox({
      prompt: `Optional note for marking #${hit.id} ${label}`,
      placeHolder: "why (stored with the finding)",
    });
    if (typed === undefined) {
      return;
    }
    note = typed;
  }
  try {
    const args = [verb, String(hit.id), ...watchlistArgs()];
    if (note) {
      args.push("--note", note);
    }
    await runCli(args);
    vscode.window.showInformationMessage(`Finding #${hit.id} marked ${label}.`);
    await provider.refresh();
  } catch (e) {
    vscode.window.showErrorMessage(`Darkwatch: ${(e as Error).message}`);
  }
}

// --------------------------------------------------------------------------- search & scans

async function search(): Promise<void> {
  if (!(await ready())) {
    return;
  }
  const query = await vscode.window.showInputBox({
    prompt: "Search stored findings (open ones; resolved and false positives are left out)",
    placeHolder: 'keywords, or a "quoted phrase"; leave empty to list all',
  });
  if (query === undefined) {
    return;
  }
  try {
    const page = JSON.parse(await runCli(["search", query, ...watchlistArgs(), "--json"])) as SearchPage;
    if (!page.hits.length) {
      vscode.window.showInformationMessage(query ? `No findings match ${query}.` : "No findings stored yet.");
      return;
    }
    const pick = await vscode.window.showQuickPick(
      page.hits.map((h) => ({
        label: `$(${SEV_ICON[h.severity] ?? "circle-outline"}) ${h.severity}  ${h.term}`,
        description: `${h.source} · ${h.signals.join(", ") || "no signals"}`,
        detail: h.title || h.url,
        hit: h,
      })),
      { title: `${page.total} finding(s) in ${page.took_ms} ms`, matchOnDescription: true, matchOnDetail: true },
    );
    if (pick) {
      await showHit(new HitItem(pick.hit));
    }
  } catch (e) {
    vscode.window.showErrorMessage(`Darkwatch: ${(e as Error).message}`);
  }
}

/** True when there is a CLI and a valid watchlist; otherwise offers the step that is missing. */
async function ready(): Promise<boolean> {
  if (state === "checking" || state === "error" || !lastDoctor) {
    await provider.refresh();
  }
  if (state === "noCli") {
    await offerInstall();
    return false;
  }
  if (state === "noWatchlist") {
    const pick = await vscode.window.showInformationMessage("Darkwatch has no watchlist yet.", "Set up");
    if (pick === "Set up") {
      await setup();
    }
    return false;
  }
  if (state === "badWatchlist") {
    const pick = await vscode.window.showErrorMessage(`The watchlist has a problem: ${lastError}`, "Open watchlist");
    if (pick) {
      await openWatchlist();
    }
    return false;
  }
  if (state === "error") {
    vscode.window.showErrorMessage(`Darkwatch: ${lastError}`, "Show log").then((p) => p && log.show());
    return false;
  }
  return true;
}

async function runScan(): Promise<void> {
  if (await ready()) {
    await runCliInTerminal("Darkwatch: scan", ["run", ...watchlistArgs(), ...(config().get<boolean>("openReportAfterScan") ? ["--open"] : [])]);
  }
}

async function deepScan(): Promise<void> {
  if (!(await ready())) {
    return;
  }
  const go = await vscode.window.showWarningMessage(
    "A deep scan checks every source, all ~900 Telegram channels, and follows onion links. It can take an hour or more. Start it?",
    { modal: true },
    "Start deep scan",
  );
  if (go === "Start deep scan") {
    await runCliInTerminal("Darkwatch: deep scan", ["run", "--deep", ...watchlistArgs()]);
  }
}

async function investigate(): Promise<void> {
  if (!(await ready())) {
    return;
  }
  const value = await vscode.window.showInputBox({
    prompt: "Investigate a value across the live sources (nothing is stored)",
    placeHolder: "an email, domain, phone, username, name or keyword",
  });
  if (value?.trim()) {
    await runCliInTerminal(`Darkwatch: investigate`, ["investigate", value.trim(), ...watchlistArgs()], false);
  }
}

async function openReport(): Promise<void> {
  if (!(await ready())) {
    return;
  }
  try {
    await runCli(["open", ...watchlistArgs()]);
  } catch (e) {
    vscode.window.showWarningMessage(`Darkwatch: ${(e as Error).message}`, "Run scan").then((p) => p && runScan());
  }
}

// --------------------------------------------------------------------------- activation

export interface DarkwatchApi {
  state(): State;
  hits(): Hit[];
  refresh(): Promise<void>;
}

export function activate(context: vscode.ExtensionContext): DarkwatchApi {
  log = vscode.window.createOutputChannel("Darkwatch");
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusBar.command = "darkwatch.hits.focus";
  statusBar.text = "$(shield) Darkwatch";
  statusBar.show();

  provider = new HitsProvider();
  view = vscode.window.createTreeView("darkwatch.hits", { treeDataProvider: provider, showCollapseAll: true });

  const reg = (id: string, fn: (...args: any[]) => unknown) =>
    context.subscriptions.push(vscode.commands.registerCommand(id, fn));
  reg("darkwatch.refresh", () => provider.refresh());
  reg("darkwatch.installCli", installCli);
  reg("darkwatch.setup", setup);
  reg("darkwatch.openWatchlist", openWatchlist);
  reg("darkwatch.runScan", runScan);
  reg("darkwatch.deepScan", deepScan);
  reg("darkwatch.openDashboard", async () => (await ready()) && runCliInTerminal("Darkwatch: dashboard", ["web", ...watchlistArgs()]));
  reg("darkwatch.openReport", openReport);
  reg("darkwatch.search", search);
  reg("darkwatch.investigate", investigate);
  reg("darkwatch.checkTor", () => runCliInTerminal("Darkwatch: Tor check", ["check-tor", ...watchlistArgs()], false));
  reg("darkwatch.doctor", () => runCliInTerminal("Darkwatch: doctor", ["doctor", ...watchlistArgs()]));
  reg("darkwatch.showLog", () => log.show());
  reg("darkwatch.showHit", showHit);
  reg("darkwatch.copyUrl", copyUrl);
  reg("darkwatch.acknowledge", (i?: HitItem) => triage(i, "ack", "acknowledged"));
  reg("darkwatch.resolve", (i?: HitItem) => triage(i, "resolve", "resolved"));
  reg("darkwatch.falsePositive", (i?: HitItem) => triage(i, "false-positive", "a false positive"));

  context.subscriptions.push(
    log, statusBar, view,
    // a changed command, watchlist or folder means a different CLI or data set
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("darkwatch")) {
        cachedCli = undefined;
        void provider.refresh();
      }
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      cachedCli = undefined;
      void provider.refresh();
    }),
    // triage in the dashboard, or a scheduled scan, changes the data behind the view
    view.onDidChangeVisibility((e) => {
      if (e.visible && Date.now() - provider.lastRefresh > 60_000) {
        void provider.refresh();
      }
    }),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (lastDoctor && path.resolve(doc.uri.fsPath) === path.resolve(lastDoctor.watchlist)) {
        void provider.refresh();
      }
    }),
  );

  void setState("checking");
  if (config().get<boolean>("refreshOnStartup", true)) {
    void provider.refresh();
  }
  return { state: () => state, hits: () => provider.hits, refresh: () => provider.refresh() };
}

export function deactivate(): void {
  // terminals own their processes and end them when closed
}
