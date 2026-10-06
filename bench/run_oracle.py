"""Runs the benchmark oracle against an app directory.

It builds the fixtures, starts the four local mocks, builds and starts the app,
runs the pytest oracle, then tears everything down even on failure and writes a
JSON result: {"items": {id: "exploitable"|"closed"|"error"},
"functional": {name: "pass"|"fail"}, "expect": ..., "ok": bool}.

Standard library only. Works on Windows, macOS, Linux.
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from urllib import request as urlrequest

HERE = os.path.dirname(os.path.abspath(__file__))
IS_WIN = os.name == "nt"


def log(*a):
    print("[run_oracle]", *a, flush=True)


def http_ok(url, timeout=1.5):
    try:
        with urlrequest.urlopen(url, timeout=timeout) as r:
            return 200 <= r.status < 500
    except Exception:
        return False


def wait_for(url, name, tries=120, delay=0.5):
    for _ in range(tries):
        if http_ok(url):
            return True
        time.sleep(delay)
    log("timed out waiting for", name, url)
    return False


def ensure_node_modules(app_dir):
    nm = os.path.join(app_dir, "node_modules")
    if os.path.isdir(nm):
        return
    src = os.path.join(HERE, "app", "node_modules")
    if not os.path.isdir(src):
        raise SystemExit("node_modules not found; run `npm install` in bench/app first")
    log("linking node_modules from", src)
    try:
        if IS_WIN:
            subprocess.run('mklink /J "%s" "%s"' % (nm, src), shell=True, check=True)
        else:
            os.symlink(src, nm)
    except Exception as e:
        log("link failed, copying instead:", repr(e))
        shutil.copytree(src, nm)


def next_bin(app_dir):
    return os.path.join(app_dir, "node_modules", "next", "dist", "bin", "next")


def spawn(cmd, cwd, env, logfile):
    out = open(logfile, "w", encoding="utf-8", errors="replace")
    kw = {}
    if not IS_WIN:
        kw["start_new_session"] = True
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT, **kw)
    p._logfh = out
    return p


def kill(p):
    if p is None or p.poll() is not None:
        return
    try:
        if IS_WIN:
            subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    except Exception:
        try:
            p.terminate()
        except Exception:
            pass
    try:
        p.wait(timeout=10)
    except Exception:
        pass
    try:
        p._logfh.close()
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-dir", default=os.path.join(HERE, "app"))
    ap.add_argument("--out", default=os.path.join(HERE, "result.json"))
    ap.add_argument("--expect", choices=["exploitable", "closed"], default="exploitable")
    ap.add_argument("--app-port", default="3100")
    ap.add_argument("--supabase-port", default="54721")
    ap.add_argument("--stripe-port", default="54722")
    ap.add_argument("--llm-port", default="54723")
    ap.add_argument("--internal-port", default="54724")
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args()

    app_dir = os.path.abspath(args.app_dir)
    fixtures_path = os.path.join(app_dir, ".bench_fixtures.json")
    logs_dir = os.path.join(HERE, ".logs")
    os.makedirs(logs_dir, exist_ok=True)

    base_env = dict(os.environ)
    base_env.update({
        "APP_PORT": args.app_port,
        "MOCK_SUPABASE_PORT": args.supabase_port,
        "MOCK_STRIPE_PORT": args.stripe_port,
        "MOCK_LLM_PORT": args.llm_port,
        "MOCK_INTERNAL_PORT": args.internal_port,
        "BENCH_APP_DIR": app_dir,
        "BENCH_FIXTURES": fixtures_path,
        "PYTHONUTF8": "1",
    })

    ensure_node_modules(app_dir)

    log("building fixtures")
    subprocess.run([sys.executable, os.path.join(HERE, "make_fixtures.py")],
                   env=base_env, check=True)

    with open(fixtures_path, "r", encoding="utf-8") as fh:
        fixtures = json.load(fh)

    if not args.no_build:
        log("building app (this reuses node_modules)")
        r = subprocess.run([shutil.which("node"), next_bin(app_dir), "build"],
                           cwd=app_dir, env=base_env)
        if r.returncode != 0:
            raise SystemExit("next build failed")

    procs = []
    result = {"expect": args.expect, "app_dir": app_dir}
    try:
        mocks = [
            ("mock_supabase", {"MIGRATIONS_DIR": os.path.join(app_dir, "supabase", "migrations")}),
            ("mock_stripe", {"STRIPE_WEBHOOK_SECRET": fixtures["webhook_secret"],
                             "APP_WEBHOOK_URL": "http://127.0.0.1:%s/api/stripe/webhook" % args.app_port,
                             "MOCK_STRIPE_PUBLIC": "http://127.0.0.1:%s" % args.stripe_port}),
            ("mock_llm", {"EXFIL_URL": "http://127.0.0.1:%s/exfil" % args.internal_port}),
            ("mock_internal", {}),
        ]
        for name, extra in mocks:
            env = dict(base_env)
            env.update(extra)
            p = spawn([sys.executable, os.path.join(HERE, "mock", name + ".py")],
                      HERE, env, os.path.join(logs_dir, name + ".log"))
            procs.append(p)

        ports = {"supabase": args.supabase_port, "stripe": args.stripe_port,
                 "llm": args.llm_port, "internal": args.internal_port}
        for name, port in ports.items():
            if not wait_for("http://127.0.0.1:%s/health" % port, name):
                raise SystemExit("mock %s did not start" % name)
        log("mocks up")

        app_env = dict(base_env)
        app_env["PORT"] = args.app_port
        app_proc = spawn([shutil.which("node"), next_bin(app_dir), "start", "-p", args.app_port],
                         app_dir, app_env, os.path.join(logs_dir, "app.log"))
        procs.append(app_proc)
        if not wait_for("http://127.0.0.1:%s/" % args.app_port, "app", tries=160):
            raise SystemExit("app did not start; see .logs/app.log")
        log("app up")

        results_path = os.path.join(HERE, ".oracle_results.json")
        if os.path.exists(results_path):
            os.remove(results_path)
        oracle_env = dict(base_env)
        oracle_env.update({
            "BENCH_EXPECT": args.expect,
            "BENCH_RESULTS": results_path,
            "APP_BASE": "http://127.0.0.1:%s" % args.app_port,
        })
        log("running oracle (expect %s)" % args.expect)
        pt = subprocess.run([sys.executable, "-m", "pytest", "-q",
                             os.path.join(HERE, "oracle")],
                            env=oracle_env)
        if os.path.exists(results_path):
            with open(results_path, "r", encoding="utf-8") as fh:
                oracle_out = json.load(fh)
            result["items"] = oracle_out.get("items", {})
            result["functional"] = oracle_out.get("functional", {})
        else:
            result["items"] = {}
            result["functional"] = {}
            result["error"] = "oracle produced no results"
        result["pytest_rc"] = pt.returncode
    finally:
        for p in reversed(procs):
            kill(p)

    items = result.get("items", {})
    # An item whose check crashed before recording (e.g. login broke) is an
    # error, not silently missing.
    with open(os.path.join(HERE, "ground_truth.json"), "r", encoding="utf-8") as fh:
        gt = json.load(fh)
    for it in gt.get("items", gt if isinstance(gt, list) else []):
        if not it.get("decoy") and it["id"] not in items:
            items[it["id"]] = "error"
    result["items"] = items
    functional = result.get("functional", {})
    items_ok = all(v == args.expect for v in items.values()) and bool(items)
    func_ok = all(v == "pass" for v in functional.values()) and bool(functional)
    result["ok"] = items_ok and func_ok
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    log("wrote", args.out)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
