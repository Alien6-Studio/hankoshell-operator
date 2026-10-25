# Production compatibility reports

Report real installations and upgrades using the
[compatibility issue form](../.github/ISSUE_TEMPLATE/compatibility_evidence.yml).
Include exact operator, Kubernetes and Keycloak versions, the installation mode,
resources used, upgrade/rollback path and any incident. The operator collects no
telemetry. [v1.0.0](https://github.com/Alien6-Studio/hankoshell-operator/releases/tag/v1.0.0)
is public; no reviewed public production compatibility report is recorded yet.

Use an anonymous installation reference: `installation-` followed by 16 random
hexadecimal digits. Reuse it for later reports from that installation. Do not
submit credentials, tenant data, hostnames, personal identifiers, raw logs,
kubeconfigs, native objects or screenshots. Follow [SECURITY.md](../SECURITY.md)
if private data was exposed.

A maintainer reviews the report and proposes an allowlisted entry in the
[compatibility registry](../tools/qualification/config/contracts/compatibility-evidence.json).
Keep source issue, privacy-review PR and incident/resolution references. Failed
or limited paths remain visible. Development builds and invented releases do
not count as public history; two fixture clusters do not prove independent
production installations.

```sh
python3 -m tools.qualification.checks.compatibility_evidence check
python3 -m tools.qualification.checks.compatibility_evidence render
```

The second command prints a readable summary. `--output /fresh/directory` writes
per-release reports for an artifact bundle; these generated reports are not
committed documentation.

A historical corpus links its actual source release and report IDs. The guard
checks the retained fixture's digest and both sides of the reference. Real
public artifact authentication and installed upgrade/rollback are separate
qualification steps. Reports never automatically graduate an API, accept a loss
or authorize publication; see [graduation criteria](stable-graduation.md).
