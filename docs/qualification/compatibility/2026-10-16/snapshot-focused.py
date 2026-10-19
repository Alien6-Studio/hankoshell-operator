"""Execute only the installed snapshot/recovery methods; not full workload qualification."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path.cwd()
spec = importlib.util.spec_from_file_location("snapshot_installed", ROOT / "scripts/workload-installed-test.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
version = sys.argv[1]
base = ROOT / ".tools/compatibility-batch"
build = json.loads((base / "oci/build.json").read_text())
args = SimpleNamespace(archive=base/"oci/image.tar", evidence=base/"oci/evidence", output=base/('snapshot-'+version+'.json'),
    kind=ROOT/".tools/qualification-bin/kind", kubectl=ROOT/".tools/qualification-bin/kubectl", helm=ROOT/".tools/qualification-bin/darwin-arm64/helm",
    oras=ROOT/".tools/qualification-bin/oras", openssl=Path('/opt/homebrew/opt/openssl@3/bin/openssl'),
    digest=build['containerimage.digest'], revision='2943933b3f6f14a3fa9bcf0487f549c1b014edf2',
    keycloak_version=version, kubernetes_version='1.37.0', deep_migration=True, node_archive=None)
module.system.publication.publish.contract.security.verify(args.evidence,args.revision,module.system.VERSION,args.digest,args.archive)
with tempfile.TemporaryDirectory(prefix='hanko-scoped-snapshot-') as directory:
    fixture=module.Installed(args,Path(directory))
    try:
        fixture.create_cluster()
        fixture.mirror_scanned_image()
        fixture.keycloak()
        fixture.provider_url='https://keycloak.auth.svc:8443'
        fixture.apply({'apiVersion':'v1','kind':'Namespace','metadata':{'name':'workload'}})
        fixture.fault_proxies()
        fixture.identities()
        fixture.install()
        fixture.start_log_capture()
        fixture.configure_api_proxy()
        fixture.snapshot_isolation()
        fixture.leak_scan()
        report=fixture.public_evidence()
        report.update(complete=True, layer='installed-snapshot-isolation', scope='scoped snapshot and lost-ACK/legacy recovery only; not full workload matrix',
            harnesses={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ('scripts/system-test.py','scripts/workload-installed-test.py')},
            helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        args.output.write_text(module.native.safe_report(report,fixture.sensitive))
    except Exception as error:
        module.system.diagnostics.capture(fixture,error)
        raise
    finally:
        fixture.cleanup()
