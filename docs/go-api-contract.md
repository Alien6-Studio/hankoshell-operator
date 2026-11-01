# Go API contract

The compiler-based checker records the exported types used by conformance
fixtures: API types, IAM contracts, adoption, applications, roles and authorization.
The reviewed snapshot is a development reference, not a published compatibility
guarantee. Operator behavior is covered by the Go tests beside its packages.

```sh
python3 -m tools.qualification.checks.go_api_contract check
python3 -m tools.qualification.checks.go_api_contract snapshot --output /tmp/go-api.json
diff -u tools/qualification/config/contracts/go-api-development.json /tmp/go-api.json
```

Review changes before updating the snapshot and its hash. The checker compares
signatures, field tags, constants, interfaces, aliases and promoted methods;
package initializers are not executed. CI never replaces its own reference.

The 17 CRDs serve and store only `hanko.sh/v1alpha1`. The separate security
inventory checks field bounds and Kubernetes permissions. Native API tests in
`api/v1alpha1/roundtrip_integration_test.go` verify typed reads and writes,
DeepCopy, status, UIDs, generations, finalizers and approval annotations. They also
reject unknown fields and conflicting SSA writers, while preserving concurrent
independently owned annotations.

Run `make preflight`, `make test` and `make integration-test` for the supported
Kubernetes versions. These checks qualify exported types and API behavior.
The first public v1.0.0 had no earlier public predecessor; qualification of later
cross-release migrations must additionally use the actual published artifacts.

The 2026-10-30 Studio review updates only `HankoThemeSpec` (two optional source
fields) and `HankoRealmSpec` (optional email-theme pointer). Existing field tags
and all other captured exports are unchanged. Keyed Go initializers continue to
work; consumers using unkeyed public struct literals must add the new fields or
move to keyed literals. This is a reviewed development snapshot update, with no
published cross-release baseline replaced.
