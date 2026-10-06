"""Shared test helpers.

Puts skills/preflight-audit/scripts on sys.path, so tests can import
_wardcore, _secret_patterns, scan_app, find_secrets and the rule modules.

Fixtures (each returns a plain function):

  write_tree(root, {relpath: text_or_bytes}) -> root
      Write files under root, creating folders. Text is written as UTF-8
      with LF line endings.

  run_script(name, *args, cwd=None, skill="preflight-audit", env=None) -> CompletedProcess
      Run a bundled script with the current interpreter. name is "scan_app.py"
      or "scan_app". stdout/stderr are decoded as UTF-8. PYTHONUTF8 is not set,
      so the scripts must force UTF-8 themselves.

  scan_rules(root, rule_ids=None, stacks=None, min_severity=None) -> scan_app.ScanResult
      Run the scan engine in process. result.findings, result.rule_ids,
      result.ctx.stacks. Pass stacks="all" to run rules whatever was detected.

  fake_token(prefix="", length=24) -> str
      A random-looking but fake token body, e.g. fake_token("sk_" + "live_").
      Bodies made of one repeated character ("x" * 24) count as placeholders
      and are NOT reported by the secret scanner, so use this instead.

  make_jwt(payload) -> str
      An unsigned JWT-shaped string with the given payload dict, e.g.
      make_jwt({"role": "service_role", "iss": "supabase"}).

Constants: REPO_ROOT, SCRIPTS_DIR.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Union

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "skills" / "preflight-audit" / "scripts"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


def _write_tree(root: Union[str, Path], files: Mapping[str, Union[str, bytes]]) -> Path:
    root = Path(root)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content)
    return root


def _run_script(name: str, *args: Any, cwd: Optional[Union[str, Path]] = None,
                skill: str = "preflight-audit", env: Optional[Dict[str, str]] = None,
                timeout: int = 180) -> subprocess.CompletedProcess:
    if not name.endswith(".py"):
        name += ".py"
    script = REPO_ROOT / "skills" / skill / "scripts" / name
    run_env = dict(os.environ)
    run_env.pop("PYTHONUTF8", None)
    run_env.pop("PYTHONIOENCODING", None)
    if env:
        run_env.update(env)
    return subprocess.run([sys.executable, str(script)] + [str(a) for a in args],
                          cwd=str(cwd) if cwd else None, capture_output=True, encoding="utf-8",
                          errors="replace", env=run_env, timeout=timeout)


def _scan_rules(root: Union[str, Path], rule_ids: Any = None, stacks: Any = None,
                min_severity: Optional[str] = None) -> Any:
    import scan_app
    return scan_app.run_scan(root, stacks=stacks, min_severity=min_severity, rule_ids=rule_ids)


_TOKEN_ALPHABET = "Q7wE9rT2yU4iO6pA8sD1fG3hJ5kL0zMcVbNn"


def _fake_token(prefix: str = "", length: int = 24) -> str:
    body = (_TOKEN_ALPHABET * (length // len(_TOKEN_ALPHABET) + 1))[:length]
    return prefix + body


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _make_jwt(payload: Mapping[str, Any]) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
    body = _b64(json.dumps(dict(payload), separators=(",", ":")).encode("utf-8"))
    return header + "." + body + "." + _fake_token("", 43)


@pytest.fixture
def write_tree():
    return _write_tree


@pytest.fixture
def run_script():
    return _run_script


@pytest.fixture
def scan_rules():
    return _scan_rules


@pytest.fixture
def fake_token():
    return _fake_token


@pytest.fixture
def make_jwt():
    return _make_jwt
