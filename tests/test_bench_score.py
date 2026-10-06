import json
import os
import subprocess
import sys

BENCH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bench")
sys.path.insert(0, BENCH)

import score  # noqa: E402


def _run(path, name, arm, items, functional, edited=()):
    data = {"run": name, "arm": arm, "items": items, "functional": functional,
            "decoys_edited": list(edited), "decoys_flagged": list(edited)}
    with open(os.path.join(path, name + ".json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh)


def test_closed_needs_working_features(tmp_path):
    items = {"V01": "closed", "V02": "closed", "H01": "closed"}
    _run(str(tmp_path), "A1", "alone", items, {"login": "pass", "chat": "fail"})
    _run(str(tmp_path), "C1", "ward", items, {"login": "pass", "chat": "pass"}, ["D05"])
    scores = {s["run"]: s for s in map(score.score_run, score.load_runs(str(tmp_path)))}
    assert scores["A1"]["planted"] == 0 and not scores["A1"]["features_ok"]
    assert scores["C1"]["planted"] == 2 and scores["C1"]["holdout"] == 1
    assert scores["C1"]["decoys_edited"] == ["D05"]


def test_open_items_listed(tmp_path):
    _run(str(tmp_path), "A1", "alone",
         {"V01": "closed", "V20": "exploitable", "H04": "error"}, {"login": "pass"})
    s = score.score_run(score.load_runs(str(tmp_path))[0])
    assert s["planted"] == 1 and s["planted_total"] == 2
    assert s["open"] == ["H04", "V20"]


def test_cli_on_committed_results():
    out = subprocess.run([sys.executable, os.path.join(BENCH, "score.py")],
                         capture_output=True, text=True, encoding="utf-8")
    assert out.returncode == 0, out.stderr
    assert "planted" in out.stdout


def test_cli_missing_dir(tmp_path):
    assert score.main(["--results", str(tmp_path / "nope")]) == 2
