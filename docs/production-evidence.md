# Production compatibility reports

The [public issue form](../.github/ISSUE_TEMPLATE/compatibility_evidence.yml)
collects voluntary, sanitized observations for #88. The operator sends no
telemetry. There are currently **no published public releases and no production
reports**. Development qualification under `docs/qualification/` remains separate.

Reports name exact source/target operator, Kubernetes and Keycloak versions,
standalone/connected mode, exercised resource kinds, actual upgrade/rollback
scenarios, incidents and migration limitations. For an initial installation,
repeat the same operator version and select `installation`. Do not call a
same-version Helm configuration rollback an operator release rollback.

Use `installation-` followed by 16 randomly generated hexadecimal digits for the
installation reference. Reuse that opaque reference for later observations of
the same installation. Never derive it from a hostname, tenant, person or cluster
UID. Two references alone do not prove independent installations; maintainers
must assess independence during the graduation review.

## Review and retention

Before submitting, remove credentials, private keys, tokens, personal data,
tenant/native object names, hostnames and company identifiers. Include abstract
behavior only. Do not attach raw logs, YAML, kubeconfigs, screenshots, provider
representations or Secret dumps. If private data was posted accidentally, remove
it and follow the repository security reporting process; do not copy it into a
review or fixture.

A maintainer reviews the issue and proposes one record in
[`compatibility-evidence.json`](compatibility-evidence.json) through a review PR.
The record uses only the allowlisted categorical fields enforced by
`scripts/compatibility-evidence.py`. It links the source issue, the review PR,
tracked incidents and their resolution PRs. No issue author, raw body or freeform
native data is copied into the registry. The mandatory `privacy_review` checks
record human review for:

- No credentials or private keys.
- No personal identifiers or tenant data.
- No raw dumps or screenshots.
- An anonymous random installation reference.
- Actual public releases and observed scenarios.

Structural validation is an additional guard, not proof that a human report is
true or private. The public release registry in the reviewed
[compatibility policy](compatibility-policy.json) is authoritative. Development
versions, unknown releases, future publication/observation dates and duplicate
source reports are refused. A failed or limited outcome needs a tracked incident;
an open incident cannot claim a resolution. Incidents and limitations remain
visible when another path passes.

Run `python3 scripts/compatibility-evidence.py render` after the reviewed record
changes. This writes the [index and per-release summaries](compatibility-evidence/README.md),
including an explicit absence of reports for releases with no evidence. The
`check` command rejects missing, extra or changed summaries and runs in preflight
and release packaging. Neither command contacts GitHub or publishes anything.

## Linking historical fixtures

When #93 reproduces a reported path, put `compatibility_reports` (report IDs) and
`source_release` in its reviewed JSON corpus metadata. Link its repository path
and exact SHA-256 in the report's `fixtures` array. The guard checks both sides,
the byte digest and the release pair. A `reproduced` migration requires a retained
fixture and an explicit `migration` scenario. Capturing and executing a genuine
published historical fixture remains #93; this metadata check does not qualify
an upgrade, rollback, conversion or stored-object migration.

The [graduation criteria](stable-graduation.md) still require two independent
installations, two public releases and a real upgrade/rollback path **per
resource**, plus all other gates. No report automatically promotes an API,
accepts a loss, extends the support window or closes an incident.
