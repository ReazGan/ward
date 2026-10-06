"""The shared scripts copied into other skills must stay byte-identical to the
canonical files in skills/preflight-audit/scripts/.

Fix a mismatch with: python .github/scripts/check_manifests.py --sync
"""

import importlib.util

import pytest

from conftest import REPO_ROOT


def _load(path):
    spec = importlib.util.spec_from_file_location(path.stem, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cm = _load(REPO_ROOT / ".github" / "scripts" / "check_manifests.py")

SKILLS = REPO_ROOT / "skills"
CANON = SKILLS / cm.CANONICAL_SKILL / "scripts"


def _pairs():
    """(skill, file) for every expected copy plus any stray copy found on disk."""
    pairs = set()
    for skill, names in cm.COPY_TARGETS.items():
        for name in names:
            pairs.add((skill, name))
    if SKILLS.is_dir():
        for d in SKILLS.iterdir():
            if not d.is_dir() or d.name == cm.CANONICAL_SKILL:
                continue
            for name in cm.SHARED_FILES:
                if (d / "scripts" / name).is_file():
                    pairs.add((d.name, name))
    return sorted(pairs)


@pytest.mark.parametrize("name", cm.SHARED_FILES)
def test_canonical_file_exists(name):
    assert (CANON / name).is_file()


@pytest.mark.parametrize("skill,name", _pairs())
def test_copy_is_byte_identical(skill, name):
    copy = SKILLS / skill / "scripts" / name
    if not copy.is_file():
        pytest.skip("skills/%s/scripts/%s is not copied yet" % (skill, name))
    assert copy.read_bytes() == (CANON / name).read_bytes(), (
        "skills/%s/scripts/%s differs from the canonical copy; run "
        "python .github/scripts/check_manifests.py --sync" % (skill, name))


@pytest.mark.parametrize("skill,name", sorted((s, n) for s, ns in cm.REF_COPY_TARGETS.items() for n in ns))
def test_reference_copy_is_byte_identical(skill, name):
    src = SKILLS / cm.REF_CANONICAL_SKILL / "references" / name
    copy = SKILLS / skill / "references" / name
    assert src.is_file(), "canonical %s is missing" % src.relative_to(REPO_ROOT).as_posix()
    assert copy.is_file(), "skills/%s/references/%s is missing; run --sync" % (skill, name)
    assert copy.read_bytes() == src.read_bytes(), (
        "skills/%s/references/%s differs from skills/%s/references/%s; run "
        "python .github/scripts/check_manifests.py --sync" % (skill, name, cm.REF_CANONICAL_SKILL, name))


def test_skills_that_import_shared_modules_carry_them():
    """A script that imports _wardcore or _secret_patterns needs the file next to it."""
    import ast

    problems = []
    for script in sorted(SKILLS.glob("*/scripts/*.py")):
        try:
            tree = ast.parse(script.read_text(encoding="utf-8"), filename=str(script))
        except SyntaxError:
            continue  # reported by test_wardcore.test_all_scripts_parse_as_python39
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                names.add(node.module.split(".")[0])
        for mod in sorted(names):
            if mod + ".py" in cm.SHARED_FILES and not (script.parent / (mod + ".py")).is_file():
                problems.append("%s imports %s but %s.py is not beside it"
                                % (script.relative_to(REPO_ROOT).as_posix(), mod, mod))
    assert problems == [], problems
