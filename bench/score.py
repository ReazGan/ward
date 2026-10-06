"""Summarize benchmark runs.

Reads bench/results/*.json (one file per run, written after run_oracle.py) and
prints, per arm, how many planted bugs and hold-outs each run closed and how
many decoys it treated as bugs. A bug only counts as closed when its exploit
check failed AND every functional check in that run passed.

    python bench/score.py [--results DIR]
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_runs(results_dir):
    runs = []
    for name in sorted(os.listdir(results_dir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(results_dir, name), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if "items" in data and "arm" in data:
            runs.append(data)
    return runs


def score_run(run):
    items = run.get("items", {})
    functional = run.get("functional", {})
    features_ok = bool(functional) and all(v == "pass" for v in functional.values())

    def closed(prefix):
        return sorted(k for k, v in items.items()
                      if k.startswith(prefix) and v == "closed" and features_ok)

    def total(prefix):
        return len([k for k in items if k.startswith(prefix)])

    return {
        "run": run.get("run", "?"),
        "arm": run["arm"],
        "planted": len(closed("V")),
        "planted_total": total("V"),
        "holdout": len(closed("H")),
        "holdout_total": total("H"),
        "features_ok": features_ok,
        "open": sorted(k for k, v in items.items() if v != "closed"),
        "decoys_edited": list(run.get("decoys_edited", [])),
        "decoys_flagged": list(run.get("decoys_flagged", [])),
    }


def render(scores):
    lines = ["%-8s %-6s %-9s %-9s %-9s %-15s %s" % (
        "arm", "run", "planted", "hold-out", "features", "decoys edited", "not closed")]
    for s in sorted(scores, key=lambda s: (s["arm"], s["run"])):
        lines.append("%-8s %-6s %-9s %-9s %-9s %-15s %s" % (
            s["arm"], s["run"],
            "%d/%d" % (s["planted"], s["planted_total"]),
            "%d/%d" % (s["holdout"], s["holdout_total"]),
            "ok" if s["features_ok"] else "BROKEN",
            ",".join(s["decoys_edited"]) or "none",
            ",".join(s["open"]) or "-"))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Summarize benchmark runs.")
    ap.add_argument("--results", default=os.path.join(HERE, "results"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if not os.path.isdir(args.results):
        print("no results dir: %s" % args.results, file=sys.stderr)
        return 2
    scores = [score_run(r) for r in load_runs(args.results)]
    if not scores:
        print("no runs found in %s" % args.results, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(scores, indent=2))
    else:
        print(render(scores))
    return 0


if __name__ == "__main__":
    sys.exit(main())
