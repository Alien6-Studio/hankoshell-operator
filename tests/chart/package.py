"""The Helm package contains installation assets, never developer test programs."""
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile

CHART = Path(__file__).resolve().parents[2] / "charts/hankoshell-operator"
FILES = {".helmignore", "Chart.yaml", "values.yaml", "README.md", "LICENSE", "NOTICE", "SECURITY.md", "icon.svg"}
with tempfile.TemporaryDirectory() as directory:
    subprocess.run(["helm", "package", str(CHART), "--destination", directory], check=True, capture_output=True)
    archive, = Path(directory).glob("*.tgz")
    with tarfile.open(archive) as package:
        names = {PurePosixPath(item.name).relative_to(CHART.name) for item in package.getmembers() if item.isfile()}
    unexpected = {name for name in names if str(name) not in FILES and name.parts[0] not in {"templates", "crds"}}
    assert not unexpected, unexpected
    assert not any(name.suffix in {".py", ".pyc", ".sh"} or "tests" in name.parts for name in names), names
    assert {PurePosixPath(name) for name in FILES} <= names
    assert len([name for name in names if name.parts[0] == "crds"]) == len(list((CHART / "crds").glob("*.yaml")))
print("Helm package: installation assets only; developer tests excluded")
