# Contributing
Bug reports, new detection patterns and new tools are all welcome. For anything bigger than a small fix, open an issue first so we can agree on the approach.

## Setting up
```bash
git clone https://github.com/FlyPhantomFly/mobile-re-mcp.git
cd mobile-re-mcp
npm ci
npm run build
```
`npx tsc --watch` rebuilds as you edit. The Python server needs Python 3.11 or newer:
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e "python[dev]"
ruff check python && pytest python/tests
```

## How the TypeScript server is laid out
`src/index.ts` registers the tools. Each tool lives in its own file under `src/tools/android/` or `src/tools/ios/`, and the shared helpers are in `src/tools/shared/`: `patterns.ts` holds every secret pattern, and `safe-exec.ts` runs external programs and checks input files.

## Adding a tool
1. Create `src/tools/<platform>/<tool-name>.ts` and export an object with `description`, `schema` (a plain object of zod fields) and `handler`.
2. Register it in `src/index.ts` with `server.registerTool`, wrapping the schema in `z.object(...)` like the others.
3. Add a row to the tools table in `README.md`.

A tool looks like this:
```typescript
import { z } from "zod";
import { checkInputFile, errorResult } from "../shared/safe-exec.js";

export const myNewTool = {
  description: "One clear sentence about what the tool reports.",
  schema: {
    apk_path: z.string().describe("Absolute path to the APK"),
  },
  handler: async (args: { apk_path: string }) => {
    const apk = checkInputFile(args.apk_path, "apk_path", [".apk"], { requireZipMagic: true });
    if (!apk.ok) return errorResult(apk.error);
    return { content: [{ type: "text" as const, text: "result" }] };
  },
};
```
Never build a shell command from tool arguments. Use `run(command, [args])` from `safe-exec.ts`, which starts the program without a shell.

## Adding a detection pattern
Add an entry to `SECRET_PATTERNS` in `src/tools/shared/patterns.ts`. Both secrets scanners pick it up.
```typescript
{
  name: "My Service API Key",
  pattern: /my-service-[A-Za-z0-9]{32}/g,
  risk: "HIGH",
  description: "My Service API key",
},
```
Risk is one of `CRITICAL`, `HIGH`, `MEDIUM` or `LOW`. To teach `ios_frameworks_detector` about an SDK, add it to `KNOWN_FRAMEWORKS` in `src/tools/ios/frameworks-detector.ts` with a category and a one-line description.

## Pull requests
Keep each one to a single change, say what changed and why, and run `npm run build` first. If you touched the Python server, run `ruff check python` and `pytest python/tests` too. If you can, try the change on a real APK or IPA, and leave sensitive details out of what you paste. Add a line to `CHANGELOG.md`.

## Releasing
This part is for maintainers. Both packages share one version number and are published from GitHub Actions through trusted publishing, so no registry tokens are stored in GitHub.
For the first npm release, publish by hand once so the package exists, then add the trusted publisher on npmjs.com under the package's Settings (owner `FlyPhantomFly`, repository `mobile-re-mcp`, workflow `publish.yml`, environment `npm-publish`, and `npm publish` ticked under Allowed actions):
```bash
npm ci && npm run build
npm pack --dry-run
npm login
npm publish --access public
```
npm does not check those fields when you save them, and a wrong one fails the workflow with ENEEDAUTH or E404. Newer trusted publishers allow only staged publishing unless you tick `npm publish`, which is the usual cause. To see what is saved, or to set it from the terminal:
```bash
npm trust list mobile-re-mcp
npm trust github mobile-re-mcp --file publish.yml --repo FlyPhantomFly/mobile-re-mcp --env npm-publish --allow-publish -y
```
For the first PyPI release, add a pending publisher on pypi.org under Your account, Publishing (project `mobile-re-mcp`, same owner and repository, workflow `publish-pypi.yml`, environment `pypi`). In GitHub, create both environments under Settings, Environments, and add yourself as a required reviewer.
For every release after that:
1. Update `CHANGELOG.md`, run `npm version <x.y.z> --no-git-tag-version`, and set the same `version` in `python/pyproject.toml`. CI fails if they differ. Commit and push.
2. Tag it (`git tag vX.Y.Z && git push origin vX.Y.Z`) and create a GitHub Release for the tag.
3. The release starts `publish.yml` for npm and `publish-pypi.yml` for PyPI. Approve both deployments when GitHub asks. Each workflow refuses to publish if the tag does not match its own version.

To test the npm login without releasing, run the Publish to npm workflow by hand (Actions, Run workflow). It prints the claims GitHub sends and npm's answer, and never publishes.

If you already published a version by hand, the workflow notices and finishes green without publishing again. If trusted publishing is not working, run `npm publish --access public` by hand, or `python -m build python && twine upload python/dist/*`, and push only the tag without creating a Release.

## Reporting issues
Use the issue templates for bugs and feature requests. Security problems go through [SECURITY.md](SECURITY.md), not a public issue.
