// Launches a real VS Code with this extension and runs ./suite against a scratch Darkwatch home.
// Needs the Darkwatch CLI installed (`uv tool install darkwatch`, or the repo's install script).

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runTests } from "@vscode/test-electron";

async function main(): Promise<void> {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "darkwatch-ext-"));
  const workspace = path.join(scratch, "workspace");
  fs.mkdirSync(workspace);
  try {
    await runTests({
      extensionDevelopmentPath: path.resolve(__dirname, "../.."),
      extensionTestsPath: path.resolve(__dirname, "suite"),
      launchArgs: [workspace, "--disable-extensions", "--user-data-dir", path.join(scratch, "user")],
      extensionTestsEnv: { DARKWATCH_HOME: path.join(scratch, "home"), DARKWATCH_TEST_SCRATCH: scratch },
    });
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
