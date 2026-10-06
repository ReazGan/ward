"""Builds a fixed copy of the app: copies bench/app into a target directory,
then overlays bench/solution on top (same relative paths). Skips build and
install artifacts so the copy is clean. Standard library only.
"""

import argparse
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "app")
SOLUTION = os.path.join(HERE, "solution")

SKIP_DIRS = {"node_modules", ".next", "__pycache__"}
SKIP_FILES = {".env.local", ".bench_fixtures.json", "package-lock.json"}


def copy_tree(src, dst):
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        rel = os.path.relpath(root, src)
        target_root = dst if rel == "." else os.path.join(dst, rel)
        os.makedirs(target_root, exist_ok=True)
        for f in files:
            if f in SKIP_FILES:
                continue
            shutil.copy2(os.path.join(root, f), os.path.join(target_root, f))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    args = ap.parse_args()
    target = os.path.abspath(args.target)
    if os.path.isdir(target):
        # keep an existing node_modules link/dir; wipe the rest
        for name in os.listdir(target):
            if name == "node_modules":
                continue
            p = os.path.join(target, name)
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                try:
                    os.remove(p)
                except OSError:
                    pass
    os.makedirs(target, exist_ok=True)
    copy_tree(APP, target)
    copy_tree(SOLUTION, target)
    print("built solution app at", target)


if __name__ == "__main__":
    main()
