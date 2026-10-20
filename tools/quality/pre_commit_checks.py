"""Run package-scoped vet and the pinned staged-secret check without shell input."""

import argparse
from pathlib import Path, PurePosixPath
import subprocess
import sys

from tools import versions

ROOT = Path(__file__).resolve().parents[2]


def packages(filenames):
    selected = set()
    for filename in filenames:
        path = PurePosixPath(filename)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("Hook filename must be repository-relative")
        if filename in ("go.mod", "go.sum"):
            return ["./..."]
        if path.suffix == ".go":
            selected.add("./" + str(path.parent))
    return sorted(selected)


def run(check, filenames):
    if check == "vet":
        selected = packages(filenames)
        if not selected:
            return 0
        command = ["go", "vet", *selected]
    else:
        binary = ROOT / ".tools/bin/hooks/gitleaks"
        actual = subprocess.check_output([str(binary), "version"], text=True, timeout=10).strip()
        if actual != versions.get("tools", "gitleaks", "version"):
            raise ValueError("Gitleaks does not match its reviewed version; run make hook-tools")
        command = [str(binary), "protect", "--staged", "--redact", "--no-banner"]
    return subprocess.run(command, cwd=ROOT, check=False).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("vet", "secrets"))
    parser.add_argument("filenames", nargs="*")
    args = parser.parse_args()
    try:
        return run(args.check, args.filenames)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("Pre-commit check failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
