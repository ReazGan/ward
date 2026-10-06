# Supply chain

Dependencies run code on the developer's machine and in CI the moment they install. The 2025-2026 npm and PyPI worms (Shai-Hulud, s1ngularity, the axios and LiteLLM compromises, ChainDrop) all used that, and most malicious releases were live for less than a week. Each section ends with the false-positive note.

## Install hardening

Two settings stop most of it: do not run dependency install scripts by default, and do not install a release younger than about a week. Add them to the project, commit the lockfile, and install from the lockfile in CI.

| Manager | Scripts off | Release age | CI install |
|---|---|---|---|
| npm 11.10+ | `.npmrc`: `ignore-scripts=true` | `.npmrc`: `min-release-age=7` (days; npm 10, bundled with Node 22, accepts the line and ignores it, so check `npm -v`) | `npm ci` |
| pnpm 10+ | off by default; allow builds with `allowBuilds` (pnpm 10.26+) or `onlyBuiltDependencies` (older pnpm 10; removed in 11) | `pnpm-workspace.yaml`: `minimumReleaseAge: 10080` (minutes; pnpm 11 defaults to 1440) | `pnpm install --frozen-lockfile` |
| Bun | off except for Bun's built-in allowlist of popular packages; list exactly what may build in `trustedDependencies` in package.json (it replaces the built-in list) | `bunfig.toml`: `[install]` `minimumReleaseAge = 604800` (seconds) | `bun install --frozen-lockfile` |
| Yarn 4 | `.yarnrc.yml`: `enableScripts: false`; allow with `dependenciesMeta.<pkg>.built: true` | `.yarnrc.yml`: `npmMinimalAgeGate: 7d` | `yarn install --immutable` |
| Yarn 1 | `.yarnrc`: `ignore-scripts true` | none, upgrade to Yarn 4 for an age gate | `yarn install --frozen-lockfile` |
| uv 0.9.17+ | `no-build = true` under `[tool.uv]` when every package ships wheels | `[tool.uv]` `exclude-newer = "7 days"` | `uv sync --locked` |
| pip 26+ | none | `--uploaded-prior-to <date>` (absolute date) | `pip install --require-hashes -r requirements.txt` (hashes pinned) |

```ini
# .npmrc (project root, committed)
ignore-scripts=true
min-release-age=7
save-exact=true
```

```yaml
# pnpm-workspace.yaml
minimumReleaseAge: 10080
allowBuilds:
  esbuild: true
  sharp: true
```

```toml
# pyproject.toml
[tool.uv]
exclude-newer = "7 days"
```

Trade-offs to tell the user:
- `ignore-scripts=true` also skips the project's own `postinstall` and the pre/post hooks of `npm run`. Run those steps by name (`npx prisma generate`, `npm run build`), and rebuild the few native packages that need it with `npm rebuild <pkg> --ignore-scripts=false` (with `ignore-scripts=true` in `.npmrc`, a plain `npm rebuild` skips the install scripts too).
- A release-age gate delays urgent security patches by the same week. Install a specific fixed version by hand when an advisory says so.
- Never set pnpm `dangerouslyAllowAllBuilds: true` to silence a build warning. Allow the one package that needs it.
- Keep one lockfile per project. A leftover `package-lock.json` next to `bun.lock` (common in app-builder exports) invites `npm install` with none of the Bun settings; delete the one you do not install with.

False positive: settings in a user-level `~/.npmrc` or set only in CI are invisible to the scanner. If they exist there, the note is already handled. pnpm 10+ blocks dependency build scripts unless allowed, and Bun runs them only for its built-in allowlist, so for them only the release age matters. pnpm 11 turns on both by default. The scanner reports this advice as info, once per package manager, and skips test, docs, example and template sub-projects.

## Known-vulnerable versions

The offline scan only knows the malicious releases below. Old versions with published CVEs (an agent copying `jsonwebtoken`, `express-jwt`, `marked` or `PyYAML` versions from an old tutorial) need the ecosystem's audit tool. These contact the package registry or the advisory database, so ask the user before running one:

```bash
npm audit --omit=dev            # or: pnpm audit --prod, yarn npm audit (Yarn 4), bun audit
pip-audit -r requirements.txt   # uv or Poetry: inside the project's virtualenv, pip-audit with no arguments
composer audit
osv-scanner scan source -r .    # every lockfile in the tree, any ecosystem
```

Report critical and high advisories for packages the app ships under Confirmed with the advisory id and the fixed version; when the user declines, list "known CVEs" under Not checked. Upgrade to the fixed version the advisory names, then re-run the tool.

False positive: an advisory for a dev-only tool (a test runner, a bundler plugin) that never runs in production is low risk; say so instead of forcing a major upgrade. Read the advisory's affected function before calling the app exposed.

## Check a package before installing

Models invent package names that sound right (about one in five suggested packages did not exist in a 2025 USENIX study) and attackers register the popular inventions. Before installing a name a coding agent suggested or added:

```bash
npm view <pkg> name version time.created repository.url   # a 404 means it does not exist: do not install
npm view <pkg> time --json                                 # release history, look for one brand new version
pip index versions <pkg>                                    # or open https://pypi.org/project/<pkg>/
```

Install it only when all of these hold:
- it exists and is the project you meant (repository and homepage resolve to that project);
- it has a real history: created more than a few weeks ago, several releases, real downloads;
- the name is not a near-copy of a popular package (an extra letter, a swapped dash, `-js`, `-py` or `-cli` added);
- it does not declare an install script or a URL dependency it does not need.

When a name fails, find the real package on the registry yourself and use that.

False positive: new internal or scoped packages exist. An offline scan cannot tell a hallucinated name from a real package added since the last install, so `supply-unlocked-dependency` is only a prompt to look.

## Known-bad versions

Releases confirmed malicious by public advisories. The scanner keeps the same list as data in `scripts/_rules_supply.py` (`KNOWN_BAD`).

| Package | Bad versions | Do this |
|---|---|---|
| `axios` (npm) | `1.14.1`, `0.30.4` | pin `1.14.0` or `0.30.3`, then follow "After a compromise". CISA alert, 2026-04-20 |
| `plain-crypto-js` (npm) | any | the dropper those axios releases pulled in; delete `node_modules/plain-crypto-js/` |
| `litellm` (PyPI) | `1.82.7`, `1.82.8` | 1.82.7 runs a payload on import, 1.82.8 ships a `.pth` file that runs at every interpreter start; install another release and rebuild the virtualenv |

Look in the lockfile, not only `package.json`: a range like `^1.14.0` resolved to `1.14.1` during the bad window shows up only in `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `uv.lock` or `poetry.lock`.

False positive: a version range in a manifest is not a finding by itself. A package whose name only starts with the same word (`axios-retry`) is a different package.

## Lifecycle script tells

`preinstall`, `install` and `postinstall` (and `prepare` for the project itself) run on every install with the user's full rights. Read them in `package.json` and in any dependency the scanner names. Signs of trouble:

- downloads: `curl`, `wget`, PowerShell `iwr` / `irm` / `iex`, `certutil -urlcache`;
- piping into an interpreter: `| sh`, `| bash`, `| node`, `| python`;
- inline code that spawns processes, makes requests or decodes a payload: `node -e` with `child_process`, `fetch`, `https.get`, `Buffer.from(..., 'base64')`, `eval`;
- worm file names: `setup_bun.js` and `bun_environment.js` (Shai-Hulud 2.0), a `preinstall` running `node setup.mjs` (ChainDrop, 2026);
- a package with no real code whose install script does all the work.

Agents add `curl ... | sh` to `postinstall` to automate a setup step. Move such a step to a documented script the user runs on purpose, with a pinned URL and a checksum.

False positive: `prisma generate`, `husky`, `patch-package`, `node-gyp rebuild`, `node install.js` in native packages (`esbuild`, `sharp`, `better-sqlite3`) and `node -e "try{require('./postinstall')}catch(e){}"` are normal. Read the script; do not delete a package on a name match alone.

## URL and git dependencies

A dependency spec that is a URL skips the registry's integrity data and malware checks. PhantomRaven (2025) packages declared `http://` tarball dependencies, so the payload never appeared on npm.

- `"pkg": "http://..."` or a plain-http index: anyone on the network path can swap the code. Remove it.
- `"pkg": "https://.../pkg.tgz"`: publish the package to the registry, or vendor the tarball into the repo and review it.
- `"pkg": "github:user/repo"`, `"user/repo#main"`, `git+https://...#v1`: a branch or tag can move. Pin a full 40-character commit hash, or use the published release.
- Python: `git+https://github.com/user/repo@<40-char-sha>#egg=pkg`, and `--index-url https://...` only.

False positive: `file:`, `link:`, `workspace:`, `npm:` aliases and private registries over https are normal. A git dependency pinned to a full commit hash is reproducible.

## After a compromise

When a known-bad version, a worm file or a download-and-run install script was installed on a machine or in CI:

1. Stop installing. Do not run `npm install` again on that tree until the lockfile is fixed.
2. Pin a clean version in `package.json` and the lockfile, then delete `node_modules` and reinstall from the lockfile with scripts off (`npm ci --ignore-scripts`, `pnpm install --frozen-lockfile --ignore-scripts`). For Python, delete and recreate the virtualenv.
3. Treat every secret that machine or CI job could read as leaked: npm and PyPI tokens, GitHub tokens and SSH keys, cloud keys, `.env` files, CI secrets. The user rotates them; see `rotation.md`.
4. Check the GitHub account for repositories, workflows or deploy keys nobody created (the 2025 worms made public repos named after the campaign, such as `s1ngularity-repository`, and added workflows that leak CI secrets).
5. Move publishing to trusted publishing (OIDC) and remove long-lived tokens from CI.
6. Add the install hardening above so the next bad release waits a week.

False positive: the scanner reports the file it saw. A worm file name inside a security tool's test fixtures, or in documentation, is not an infection; check where it sits before calling it one.

LAST-VERIFIED: 2026-10-06
