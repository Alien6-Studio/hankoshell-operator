# Administrator finalizer release qualification

The administrator CLI now supports a short-lived plan, distinct authenticated
approval, immutable audit intent, one selective compare-and-swap removal and
read-only target observation after interruption. The operator gains no recovery
role. [The procedure](../../../../finalizer-recovery.md) explains the privileged
administrator boundary, maintenance freeze, orphaned provider state, Kubernetes
garbage collection and audit retention limits.

[validation.json](validation.json) binds the actual CLI, policy, RBAC and fixtures
to development source `48e94019780ea752eca489ad62e1f83e2f549057`. Each supported
Kubernetes version passed 779 race-enabled API cases with no failures, skips,
dirty source or source change. Eight cases per version cover the real CLI and
adversarial audit admission. The CLI witness uses distinct identities, preserves
a foreign Role finalizer and refuses target replay. Sixteen Python state-machine
tests cover stale authority, audit failures, races and uncertain acknowledgements.

The final preflight, including all 443 Python tests, hooks and chart checks passed
on follow-up `f0645a09dc3375b88cc45f37a10b2aac42078ab4`. Tagged lint reports zero
issues. This follow-up changes only the CRD inventory regression fixture and an
ADR source link; the JSON manifest verifies that API-qualified components are
byte-identical to the original qualification source. Local full results and
logs remain under `.tools/finalizer-recovery-batch/`; their hashes are retained
in the public summary. CI preserves its own JUnit outcomes for each API job.

The preceding integration head failed Linux preflight because an unordered glob
selected a multi-version CRD for an unregistered future kind. The regression now
uses both single-version and multi-version donors explicitly and copies only the
reviewed hub version. Kind/registration and invalid served-version refusals remain
strict. This correction is locally verified, not a claim of remote CI success.

These are disposable API-server tests. They do not qualify provider cleanup,
node garbage collection, a connected audit recorder, production HA or a public
predecessor upgrade. The full protected integration pipeline remains mandatory.
No release, registry publication or protection bypass was performed.
