#!/usr/bin/env python3
"""Check architecture decision references in repository Go, YAML and Markdown."""

from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
DECISIONS = Path("docs/architecture/decisions")
SUFFIXES = {".go", ".yaml", ".yml", ".md"}
REFERENCE = re.compile(r"\bADR-\d+(?:/\d+)*\b")
RECORD = re.compile(r"ADR-([0-9]{3,})-[a-z0-9]+(?:-[a-z0-9]+)*\.md")
CATALOG_FILES = {DECISIONS / "README.md", DECISIONS / "TEMPLATE.md"}


def repository_files(root):
    # Include untracked contributor files, hidden YAML and generated manifests,
    # but never ignored tools, caches or evidence. NUL delimiters preserve paths.
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30,
    )
    return sorted({Path(name) for name in result.stdout.decode("utf-8").split("\0")
                   if name and Path(name).suffix in SUFFIXES and (root / name).exists()})


def reference_ids(text):
    # Retain support for inherited shorthand such as ADR-009/010.
    for match in REFERENCE.finditer(text):
        for number in match.group()[4:].split("/"):
            yield f"ADR-{int(number):03d}"


def check(root=ROOT, paths=None):
    root = Path(root)
    paths = repository_files(root) if paths is None else sorted(set(paths))
    contents = {path: (root / path).read_text(encoding="utf-8") for path in paths
                if path.suffix in SUFFIXES}
    records = {}
    errors = []
    for path, content in contents.items():
        if path.parent != DECISIONS or path in CATALOG_FILES:
            continue
        match = RECORD.fullmatch(path.name)
        if not match or int(match[1]) == 0 or match[1] != f"{int(match[1]):03d}":
            errors.append(f"{path}: expected ADR-NNN-lowercase-title.md (positive, padded number)")
            continue
        identity = f"ADR-{match[1]}"
        if identity in records:
            errors.append(f"{path}: duplicate {identity}; already defined in {records[identity]}")
            continue
        records[identity] = path
        if not re.search(rf"^# {identity}: .+", content, re.MULTILINE):
            errors.append(f"{path}: title must start with '# {identity}: '")
        if not re.search(r"^Status: Accepted\s*$", content, re.MULTILINE):
            errors.append(f"{path}: reconstructed decision must have Status: Accepted")
        for section in ("Context", "Decision", "Consequences", "Enforcement"):
            if f"\n## {section}\n" not in content:
                errors.append(f"{path}: missing {section} section")
    if not records:
        errors.append(f"{DECISIONS}: no architecture decisions found")

    referenced = set()
    for path, content in contents.items():
        for line_number, line in enumerate(content.splitlines(), 1):
            for identity in reference_ids(line):
                target = records.get(identity)
                if target is None:
                    errors.append(f"{path}:{line_number}: {identity} has no decision record")
                elif path != target and path not in CATALOG_FILES:
                    # A title, template or index entry cannot keep an orphan alive.
                    referenced.add(identity)
    for identity, path in records.items():
        if identity not in referenced:
            errors.append(f"{path}: {identity} is not referenced outside itself and the index/template")
    if errors:
        raise ValueError("\n".join(errors))
    return len(records)


def main():
    try:
        count = check()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"ADR reference check failed:\n{error}", file=sys.stderr)
        return 1
    print(f"ADR references resolve to {count} accepted, referenced decisions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
