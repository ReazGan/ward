"""Write references/rules.md from the RULES lists in the _rules_*.py modules.

Usage:
  python3 gen_rules_md.py            write ../references/rules.md
  python3 gen_rules_md.py --check    exit 1 if the committed file is out of date
  python3 gen_rules_md.py --output FILE

A maintainer and CI step: agents using the skill read rules.md or run
scan_app.py --explain, they never need to run this. Exit codes: 0 written or
up to date, 1 out of date (--check), 2 a rule module failed to load or the
file cannot be written.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import _wardcore as wc  # noqa: E402
import scan_app  # noqa: E402

DEFAULT_OUT = _HERE.parent / "references" / "rules.md"

SECTION_TITLES: Dict[str, str] = {
    "_rules_dataauth": "Data access and auth",
    "_rules_secrets": "Secrets reaching the client",
    "_rules_logic": "Payments, abuse and request logic",
    "_rules_injection": "Injection, XSS, uploads and SSRF",
    "_rules_deploy": "Deployment and configuration",
    "_rules_supply": "Supply chain",
}

HEADER = """# Rule reference

<!-- Generated from the RULES lists in scripts/_rules_*.py by gen_rules_md.py (a maintainer and CI step). Do not edit by hand. -->

One entry per rule that `scripts/scan_app.py` can report. Find a finding's entry by its rule id, or print only the entries you need with `python3 scripts/scan_app.py --explain RULE_ID[,RULE_ID]`.

Each entry says what the rule looks for, why coding agents produce it, the false-positive trap to rule out before you report it, and where the fix is. The scanner reports candidates. Read the code at the reported line and confirm the problem before fixing anything.

The severity shown is the rule's default. A check can report one hit higher or lower when the code around it is stronger or weaker evidence; the scan output shows the severity of each hit.
"""


def _one_line(text: str) -> str:
    return " ".join((text or "").split())


def _fix(ref: str) -> str:
    ref = (ref or "").strip()
    if not ref:
        return "-"
    target = ref.split("#", 1)[0]
    if target.endswith(".md") and " " not in ref:
        return "[%s](%s)" % (ref, ref)
    return ref


def render(rules: Sequence[wc.Rule]) -> str:
    """The full rules.md text for these rules (LF newlines, stable order)."""
    order = {m: i for i, m in enumerate(scan_app.RULE_MODULES)}
    by_module: Dict[str, List[wc.Rule]] = {}
    for r in rules:
        by_module.setdefault(r.module or "other", []).append(r)
    lines = HEADER.rstrip("\n").split("\n")
    total = sum(len(v) for v in by_module.values())
    lines += ["", "Rules: %d." % total]
    for module in sorted(by_module, key=lambda m: (order.get(m, 99), m)):
        items = sorted(by_module[module], key=lambda r: (wc.SEVERITY_RANK.get(r.severity, 9), r.id))
        title = SECTION_TITLES.get(module, module)
        lines += ["", "## %s" % title, "", "Module: `scripts/%s.py`" % module]
        for r in items:
            stacks = ", ".join(r.stacks)
            confirm = "confirm before reporting" if r.needs_confirmation else "direct"
            sev = "**%s**" % r.severity
            if r.severity_note:
                sev += " (%s)" % _one_line(r.severity_note)
            lines += [
                "",
                "### %s" % r.id,
                "",
                "%s | confidence %s | %s | stacks: %s" % (sev, r.confidence, confirm, stacks),
                "",
                "- What: %s" % _one_line(r.message),
                "- Class: %s" % _one_line(r.klass),
                "- Why agents produce it: %s" % (_one_line(r.why) or "-"),
                "- False-positive trap: %s" % (_one_line(r.fp_trap) or "-"),
                "- Fix: %s" % _fix(r.fix_ref),
            ]
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    wc.setup_io()
    ap = argparse.ArgumentParser(prog="gen_rules_md.py",
                                 description="Write references/rules.md from the rule modules.")
    ap.add_argument("--check", action="store_true", help="exit 1 if the file differs from the rule modules")
    ap.add_argument("--output", metavar="FILE", help="write here instead of references/rules.md")
    args = ap.parse_args(argv)

    rules, warnings = scan_app.load_rules()
    if warnings:
        for w in warnings:
            sys.stderr.write("error: %s\n" % w)
        return wc.EXIT_ERROR
    text = render(rules)
    out = wc.norm(args.output) if args.output else DEFAULT_OUT

    if args.check:
        current = wc.read_text(out) if out.exists() else None
        if current is None or current.replace("\r\n", "\n") != text:
            sys.stderr.write("%s is out of date. Run: python3 scripts/gen_rules_md.py\n" % out.as_posix())
            return wc.EXIT_FINDINGS
        sys.stdout.write("%s is up to date (%d rules)\n" % (out.as_posix(), len(rules)))
        return wc.EXIT_OK

    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    except OSError as exc:
        sys.stderr.write("error: cannot write %s: %s\n" % (out, exc))
        return wc.EXIT_ERROR
    sys.stdout.write("wrote %s (%d rules)\n" % (out.as_posix(), len(rules)))
    return wc.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
