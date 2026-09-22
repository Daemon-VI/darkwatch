# Publishing the Darkwatch VS Code extension

The extension publishes to two registries under the **`daemon-vi`** publisher:

- **VS Code Marketplace** — https://marketplace.visualstudio.com/items?itemName=daemon-vi.darkwatch
- **Open VSX** — https://open-vsx.org/extension/daemon-vi/darkwatch

Publishing is done by CI (`.github/workflows/publish-vscode.yml`) on a `vscode-v*` tag. You only
touch tokens once.

## One-time setup

### Tokens

1. **`VSCE_PAT`** (Marketplace) — from **Azure DevOps**, not the Azure portal:
   - Open https://dev.azure.com/_usersSettings/tokens (create an empty org at
     https://aex.dev.azure.com/ first if it bounces you).
   - Sign in with the Microsoft account that owns the `daemon-vi` publisher.
   - **+ New Token** → Organization **All accessible organizations** → Scopes: *Show all scopes* →
     **Marketplace → Manage** → **Create**. Copy it (shown once).
2. **`OVSX_PAT`** (Open VSX) — from https://open-vsx.org (GitHub login):
   - Sign the **Eclipse Open VSX Publisher Agreement** once (account settings).
   - **Settings → Access Tokens → Generate New Token**. Copy it.
   - If a publish ever fails with "namespace not owned", claim it once:
     `npx ovsx create-namespace daemon-vi -p <OVSX_PAT>`.

### GitHub secrets

Add both at
https://github.com/Daemon-VI/darkwatch/settings/secrets/actions
(**New repository secret**):

| Secret | Value |
|---|---|
| `VSCE_PAT` | the Azure DevOps token |
| `OVSX_PAT` | the Open VSX token |

Never paste a token into a chat, a file, or a commit. Enter them only in the browser fields above.
Each publish step in the workflow is skipped when its secret is absent, so a run with neither just
packages and uploads the `.vsix` as a build artifact — a safe dry run.

## Releasing a version

1. Make and test the change:
   ```
   cd vscode-extension
   npm install
   npm run compile && npm run lint
   npm test               # launches VS Code; needs the darkwatch CLI installed
   npm run package        # sanity-check the .vsix locally
   ```
2. **Bump `version`** in `vscode-extension/package.json` (the Marketplace rejects a duplicate
   version), and add a `CHANGELOG.md` entry.
3. Commit, then tag and push — the tag is what triggers the publish:
   ```
   git commit -am "vscode extension vX.Y.Z"
   git push origin main
   git tag vscode-vX.Y.Z
   git push origin vscode-vX.Y.Z
   ```
4. Watch it at https://github.com/Daemon-VI/darkwatch/actions ("Publish VS Code extension").
   You can also run the workflow by hand from that tab (workflow_dispatch) without a tag.

## Verify

- Marketplace API (immediate):
  ```
  curl -sX POST https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery \
    -H "Accept: application/json;api-version=7.1-preview.1" -H "Content-Type: application/json" \
    -d '{"filters":[{"criteria":[{"filterType":7,"value":"daemon-vi.darkwatch"}]}],"flags":914}'
  ```
- Open VSX (indexes a few minutes after publish): `curl -s https://open-vsx.org/api/daemon-vi/darkwatch/latest`
- Install from either: `code --install-extension daemon-vi.darkwatch`

## Notes

- The extension is a front end over the `darkwatch` CLI. It reads data via `darkwatch hits --json`
  and `darkwatch search --json`; scans and the dashboard run in a terminal. It never opens an
  evidence URL. Keep those two CLI flags stable — they are the extension's contract.
- v0.1.0 first published 2026-09-21 (Marketplace confirmed; Open VSX from the same run).
- v0.2.0 needs CLI 0.5.0+ (it calls `darkwatch doctor --json` and `darkwatch setup`). Keep those stable too.
