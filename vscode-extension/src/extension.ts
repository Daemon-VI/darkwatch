// Darkwatch VS Code extension.
//
// A thin, safe front end over the `darkwatch` CLI. It never opens an evidence URL in a browser —
// exactly as the dashboard does not — because those URLs point at leak sites and onion services;
// they are shown as text and copied on request only. Data is read through `darkwatch hits --json`
// and `darkwatch search --json`; scans and the dashboard run in an integrated terminal so their
// progress (and Tor bootstrap) is visible.

import { spawn } from "child_process";
import * as vscode from "vscode";

type Hit = {
  id: number;
  severity: string;
  score: number;
  target: string;
  term: string;
  term_type: string;
  source: string;
  status: string;
  title: string;
  url: string;
  signals: string[];
  snippet: string;
  first_seen?: string;
  last_seen?: string;
  note?: string;
};

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
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

function config() {
  return vscode.workspace.getConfiguration("darkwatch");
}

function workdir(): string | undefined {
  const cwd = config().get<string>("cwd");
  if (cwd && cwd.trim()) {
    return cwd;
  }
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

/** Run the CLI and return stdout. Rejects with a readable message on failure. */
function runCli(args: string[]): Promise<string> {
  const command = config().get<string[]>("command") ?? ["darkwatch"];
  const watchlist = config().get<string>("watchlist") || "watchlist.yaml";
  const cwd = workdir();
  const [exe, ...fixed] = command;
  const full = [...fixed, ...args, "--watchlist", watchlist];
  return new Promise((resolve, reject) => {
    if (!exe) {
      reject(new Error("darkwatch.command is empty; set it in Settings."));
      return;
    }
    // shell:false and an argv array: search/investigate values can never be shell-interpreted.
    const child = spawn(exe, full, { cwd, shell: false });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d.toString()));
    child.stderr.on("data", (d) => (err += d.toString()));
    child.on("error", (e) => {
      reject(
        new Error(
          `could not run '${exe}': ${e.message}. Set darkwatch.command (e.g. ["uv","run","darkwatch"]).`
        )
      );
    });
    child.on("close", (code) => {
      if (code === 0) {
        resolve(out);
      } else {
        reject(new Error(err.trim() || out.trim() || `darkwatch exited ${code}`));
      }
    });
  });
}

/** Run a CLI command in an integrated terminal so its progress is visible. */
function runInTerminal(name: string, args: string[]): void {
  const command = config().get<string[]>("command") ?? ["darkwatch"];
  const watchlist = config().get<string>("watchlist") || "watchlist.yaml";
  const cwd = workdir();
  const term = vscode.window.createTerminal({ name, cwd });
  const quoted = [...command, ...args, "--watchlist", watchlist]
    .map((a) => (/[\s"']/.test(a) ? JSON.stringify(a) : a))
    .join(" ");
  term.show();
  term.sendText(quoted);
}

// --------------------------------------------------------------------------- tree

class SeverityGroup extends vscode.TreeItem {
  constructor(public readonly severity: string, public readonly hits: Hit[]) {
    super(`${severity} (${hits.length})`, vscode.TreeItemCollapsibleState.Expanded);
    this.iconPath = new vscode.ThemeIcon(
      SEV_ICON[severity] ?? "circle-outline",
      new vscode.ThemeColor(SEV_COLOR[severity] ?? "foreground")
    );
    this.contextValue = "severity";
  }
}

class HitItem extends vscode.TreeItem {
  constructor(public readonly hit: Hit) {
    super(`${hit.term}`, vscode.TreeItemCollapsibleState.None);
    this.description = `${hit.source}${hit.signals.length ? "  ·  " + hit.signals.join(", ") : ""}`;
    this.tooltip = new vscode.MarkdownString(
      [
        `**${hit.severity}** · score ${hit.score} · ${hit.status}`,
        `**${hit.term}** (${hit.term_type}) — ${hit.target}`,
        hit.title ? `\n${hit.title}` : "",
        hit.snippet ? `\n\n${hit.snippet}` : "",
        "\n\n*Evidence URL is shown in details; it is never opened for you.*",
      ].join("\n")
    );
    this.iconPath = new vscode.ThemeIcon(
      SEV_ICON[hit.severity] ?? "circle-outline",
      new vscode.ThemeColor(SEV_COLOR[hit.severity] ?? "foreground")
    );
    this.contextValue = "hit";
    this.command = {
      command: "darkwatch.showHit",
      title: "Show Finding Details",
      arguments: [this],
    };
  }
}

class HitsProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private readonly _changed = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._changed.event;
  private groups: SeverityGroup[] = [];
  private error: string | undefined;

  getTreeItem(e: vscode.TreeItem): vscode.TreeItem {
    return e;
  }

  getChildren(element?: vscode.TreeItem): vscode.TreeItem[] {
    if (this.error) {
      const item = new vscode.TreeItem(this.error);
      item.iconPath = new vscode.ThemeIcon("warning");
      return element ? [] : [item];
    }
    if (!element) {
      return this.groups;
    }
    if (element instanceof SeverityGroup) {
      return element.hits.map((h) => new HitItem(h));
    }
    return [];
  }

  async refresh(): Promise<void> {
    try {
      const raw = await runCli(["hits", "--json"]);
      const hits: Hit[] = JSON.parse(raw || "[]");
      this.error = undefined;
      this.groups = SEVERITIES.map(
        (sev) => new SeverityGroup(sev, hits.filter((h) => h.severity === sev))
      ).filter((g) => g.hits.length > 0);
      const open = hits.filter((h) => h.severity === "CRITICAL" || h.severity === "HIGH").length;
      statusBar.text = `$(shield) Darkwatch: ${hits.length}`;
      statusBar.tooltip = `${hits.length} open finding(s)` + (open ? `, ${open} CRITICAL/HIGH` : "");
      statusBar.color = open ? new vscode.ThemeColor("charts.orange") : undefined;
    } catch (e) {
      this.error = `Darkwatch: ${(e as Error).message}`;
      this.groups = [];
      statusBar.text = "$(shield) Darkwatch: !";
      statusBar.tooltip = this.error;
    }
    this._changed.fire();
  }
}

let statusBar: vscode.StatusBarItem;
let provider: HitsProvider;

// --------------------------------------------------------------------------- details & triage

async function showHit(item?: HitItem): Promise<void> {
  const hit = item?.hit;
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
  ].filter((l) => l !== "");
  const doc = await vscode.workspace.openTextDocument({
    content: lines.join("\n"),
    language: "text",
  });
  await vscode.window.showTextDocument(doc, { preview: true });
}

async function copyUrl(item?: HitItem): Promise<void> {
  const hit = item?.hit;
  if (!hit) {
    return;
  }
  await vscode.env.clipboard.writeText(hit.url);
  vscode.window.showInformationMessage("Evidence URL copied to the clipboard.");
}

async function triage(item: HitItem | undefined, verb: string, label: string): Promise<void> {
  const hit = item?.hit;
  if (!hit) {
    return;
  }
  let note = "";
  if (verb === "false-positive" || verb === "resolve") {
    note =
      (await vscode.window.showInputBox({
        prompt: `Optional note for marking #${hit.id} ${label}`,
        placeHolder: "why (stored with the finding)",
      })) ?? "";
  }
  try {
    const args = ["ack", String(hit.id)];
    args[0] = verb;
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

// --------------------------------------------------------------------------- search

async function search(): Promise<void> {
  const query = await vscode.window.showInputBox({
    prompt: "Search stored findings",
    placeHolder: 'keywords, or a "quoted phrase"',
  });
  if (query === undefined) {
    return;
  }
  try {
    const raw = await runCli(["search", query, "--json"]);
    const page = JSON.parse(raw) as { hits: Hit[]; total: number; took_ms: number };
    if (!page.hits.length) {
      vscode.window.showInformationMessage(`No findings match ${query || "the filter"}.`);
      return;
    }
    const pick = await vscode.window.showQuickPick(
      page.hits.map((h) => ({
        label: `$(${SEV_ICON[h.severity] ?? "circle-outline"}) ${h.severity}  ${h.term}`,
        description: `${h.source} · ${h.signals.join(", ") || "no signals"}`,
        detail: h.title || h.url,
        hit: h,
      })),
      {
        title: `${page.total} finding(s) in ${page.took_ms} ms`,
        matchOnDescription: true,
        matchOnDetail: true,
      }
    );
    if (pick) {
      await showHit(new HitItem(pick.hit));
    }
  } catch (e) {
    vscode.window.showErrorMessage(`Darkwatch: ${(e as Error).message}`);
  }
}

async function investigate(): Promise<void> {
  const value = await vscode.window.showInputBox({
    prompt: "Investigate a value across the live sources (nothing is stored)",
    placeHolder: "an email, domain, phone, username, name or keyword",
  });
  if (!value) {
    return;
  }
  // live and possibly slow (Tor): run in a terminal so progress shows
  runInTerminal(`Darkwatch: investigate ${value}`, ["investigate", value]);
}

async function deepScan(): Promise<void> {
  const go = await vscode.window.showWarningMessage(
    "A deep scan checks every source, all ~940 Telegram channels, and follows onion links. It can take an hour or more. Start it?",
    { modal: true },
    "Start deep scan"
  );
  if (go === "Start deep scan") {
    runInTerminal("Darkwatch: deep scan", ["run", "--deep"]);
  }
}

// --------------------------------------------------------------------------- activation

export function activate(context: vscode.ExtensionContext): void {
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusBar.command = "darkwatch.hits.focus";
  statusBar.text = "$(shield) Darkwatch";
  statusBar.show();

  provider = new HitsProvider();
  const view = vscode.window.createTreeView("darkwatch.hits", { treeDataProvider: provider });

  const reg = (id: string, fn: (...a: any[]) => any) =>
    context.subscriptions.push(vscode.commands.registerCommand(id, fn));

  reg("darkwatch.refresh", () => provider.refresh());
  reg("darkwatch.runScan", () => runInTerminal("Darkwatch: scan", ["run", "--open"]));
  reg("darkwatch.deepScan", deepScan);
  reg("darkwatch.openDashboard", () => runInTerminal("Darkwatch: dashboard", ["web"]));
  reg("darkwatch.search", search);
  reg("darkwatch.investigate", investigate);
  reg("darkwatch.showHit", showHit);
  reg("darkwatch.copyUrl", copyUrl);
  reg("darkwatch.acknowledge", (i?: HitItem) => triage(i, "ack", "acknowledged"));
  reg("darkwatch.resolve", (i?: HitItem) => triage(i, "resolve", "resolved"));
  reg("darkwatch.falsePositive", (i?: HitItem) => triage(i, "false-positive", "a false positive"));

  context.subscriptions.push(statusBar, view);

  if (config().get<boolean>("refreshOnStartup", true)) {
    void provider.refresh();
  }
}

export function deactivate(): void {
  // nothing to tear down: no long-lived processes are owned here
}
