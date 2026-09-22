// End-to-end checks inside VS Code: every state the view can be in, and every command that acts
// on a finding, against the real CLI and a scratch Darkwatch home (DARKWATCH_HOME).

import * as assert from "assert";
import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

type Api = { state(): string; hits(): { id: number; url: string; status: string; term: string }[]; refresh(): Promise<void> };

function darkwatch(args: string[]): string {
  const exe = [process.env.UV_TOOL_BIN_DIR, path.join(process.env.USERPROFILE ?? process.env.HOME ?? "", ".local", "bin")]
    .filter((d): d is string => !!d)
    .map((d) => path.join(d, process.platform === "win32" ? "darkwatch.exe" : "darkwatch"))
    .find((p) => fs.existsSync(p)) ?? "darkwatch";
  return execFileSync(exe, args, { encoding: "utf-8", env: { ...process.env, PYTHONIOENCODING: "utf-8" } });
}

async function step(name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
    console.log(`  ok  ${name}`);
  } catch (e) {
    console.log(`  FAIL ${name}`);
    throw e;
  }
}

export async function run(): Promise<void> {
  const ext = vscode.extensions.getExtension("daemon-vi.darkwatch")!;
  const api = (await ext.activate()) as Api;
  const scratch = process.env.DARKWATCH_TEST_SCRATCH!;
  const home = process.env.DARKWATCH_HOME!;

  await step("every contributed command is registered", async () => {
    const all = new Set(await vscode.commands.getCommands(true));
    const declared = ext.packageJSON.contributes.commands.map((c: { command: string }) => c.command);
    assert.deepStrictEqual(declared.filter((c: string) => !all.has(c)), []);
  });

  await step("no watchlist -> the set-up state", async () => {
    await api.refresh();
    assert.strictEqual(api.state(), "noWatchlist");
  });

  await step("a watchlist in the Darkwatch home is found from any folder -> empty", async () => {
    darkwatch(["setup", "--name", "Asha Rao", "--email", "asha.rao@example.com", "--no-prompt"]);
    assert.ok(fs.existsSync(path.join(home, "watchlist.yaml")));
    await api.refresh();
    assert.strictEqual(api.state(), "empty");
  });

  await step("stored findings -> the tree", async () => {
    const dump = path.join(scratch, "dump.txt");
    fs.writeFileSync(dump, "combolist\nasha.rao@example.com:hunter2\nother@example.org:pass\n");
    darkwatch(["scan-text", dump, "--save"]);
    await api.refresh();
    assert.strictEqual(api.state(), "ready");
    assert.ok(api.hits().length >= 1);
  });

  await step("show details opens the finding, never its URL", async () => {
    const hit = api.hits()[0];
    await vscode.commands.executeCommand("darkwatch.showHit", { hit });
    const text = vscode.window.activeTextEditor?.document.getText() ?? "";
    assert.ok(text.includes(`finding #${hit.id}`), text);
  });

  await step("copy URL puts the evidence URL on the clipboard", async () => {
    const hit = api.hits()[0];
    await vscode.env.clipboard.writeText("");
    await vscode.commands.executeCommand("darkwatch.copyUrl", { hit });
    assert.strictEqual(await vscode.env.clipboard.readText(), hit.url);
  });

  await step("acknowledge changes the status through the CLI", async () => {
    const hit = api.hits()[0];
    await vscode.commands.executeCommand("darkwatch.acknowledge", { hit });
    const after = api.hits().find((h) => h.id === hit.id);
    assert.strictEqual(after?.status, "acknowledged");
  });

  await step("a broken watchlist -> its own state, not an empty view", async () => {
    const file = path.join(home, "watchlist.yaml");
    const good = fs.readFileSync(file, "utf-8");
    fs.writeFileSync(file, good + "\nbogus_key: 1\n");
    await api.refresh();
    assert.strictEqual(api.state(), "badWatchlist");
    fs.writeFileSync(file, good);
  });

  await step("a CLI that cannot be found -> the install state", async () => {
    const cfg = vscode.workspace.getConfiguration("darkwatch");
    await cfg.update("command", ["darkwatch-not-installed-here"], vscode.ConfigurationTarget.Global);
    await api.refresh();
    assert.strictEqual(api.state(), "noCli");
    await cfg.update("command", undefined, vscode.ConfigurationTarget.Global);
    await api.refresh();
    assert.strictEqual(api.state(), "ready");
  });
}
