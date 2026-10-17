"""Build and test the experimental SPI for one reviewed Keycloak SDK, without publishing."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

import versions
import keycloak_extension_source as extension

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("go_tests", ROOT / "scripts/go-tests.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def build():
    version = os.environ.get("KEYCLOAK_VERSION", versions.get("keycloak", "default"))
    if version not in versions.get("keycloak", "versions"):
        raise ValueError("Unreviewed Keycloak SDK")
    source = runner.checkout_identity()
    dependency = extension.pin()
    module = extension.checkout()
    target = module / "target" / version
    manifest = target / "build.json"
    manifest.unlink(missing_ok=True)
    command = ["mvn", "-B", "-ntp", "-Dkeycloak.version=" + version,
               "-Dmaven.repo.local=" + str(ROOT / ".tools/delegation-maven"), "-f", str(module / "pom.xml"), "clean", "verify"]
    subprocess.run(command, cwd=ROOT, check=True)
    cases = []
    for path in sorted((target / "surefire-reports").glob("TEST-*.xml")):
        suite = ET.parse(path).getroot()
        if suite.tag != "testsuite" or any(int(suite.get(key, "0")) for key in ("failures", "errors", "skipped")):
            raise ValueError("Java qualification requires all tests to pass without skips")
        cases += [case.get("classname", "") + "/" + case.get("name", "") for case in suite.findall("testcase")]
    if len(cases) < 15 or len(cases) != len(set(cases)):
        raise ValueError("Missing or duplicate Java test evidence")
    extension.verify(module, dependency)
    if runner.checkout_identity() != source or extension.pin() != dependency:
        raise ValueError("Checkout changed during the extension build")
    jar = target / ("bounded-delegation-keycloak-" + version + ".jar")
    if not jar.is_file() or not 0 < jar.stat().st_size <= 5 * 1024 * 1024:
        raise ValueError("Missing or oversized extension artifact")
    manifest.write_text(json.dumps({"schema": 1, "experimental": True, "keycloak": version,
        "revision": source[0], "worktree_dirty": source[1], "jar_sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
        "extension": dependency, "java_tests": cases}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(build())
    except (OSError, ValueError, subprocess.SubprocessError, ET.ParseError) as error:
        print("Extension build failed: " + str(error), file=sys.stderr)
        raise SystemExit(1) from error
