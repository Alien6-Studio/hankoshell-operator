# Try the operator locally

Run the three README journeys on a disposable kind cluster. The script installs
the published operator and OCI Helm chart for the version in `versions.json`,
pins the operator image to its release digest, and starts an HTTPS Keycloak with
temporary credentials. No Go build, platform account or existing Keycloak is needed.

You need Bash, a running Docker engine, kind, kubectl, Helm, OpenSSL, curl and jq.
Use the kind/kubectl/Helm versions recorded in [versions.json](../../versions.json).
Allow several minutes for the initial image downloads and enough Docker memory
for a Kubernetes node and Keycloak (the fixture gives Keycloak a 2 GiB limit).

From the repository root:

```sh
./examples/kind/demo.sh up
```

The script creates a uniquely named cluster and prints three `PASS` results:

1. An OIDC SPA client exists in Keycloak with the declared callback.
2. A pre-existing client passes through Observe, exact-candidate approval and a
   separate Manage transition, retaining its original UUID.
3. A worker uses the operator-created Secret to obtain a real OAuth
   `client_credentials` token. Tokens and credentials are never printed.

Inspect and rerun verification:

```sh
kubectl --kubeconfig .tools/kind-demo/kubeconfig -n auth get hankoapplication,hankoserviceaccount
./examples/kind/demo.sh verify
```

Edit [identities.yaml](identities.yaml), apply it using that same kubeconfig and
inspect the resulting status. The declared callback hosts are illustrative; this
example verifies client registration rather than hosting a browser application.

```sh
./examples/kind/demo.sh down
```

Cleanup verifies the recorded cluster container identity, deletes that cluster
and removes its private state. Repeating `down` is safe. Existing kubeconfigs and
clusters are not modified. A failed setup leaves its state for inspection and
the same cleanup command; run `down` before starting a new demonstration.

This is an isolated learning environment: Keycloak uses `start-dev`, ephemeral
storage and a one-day local certificate. The stock kind network does not enforce
the rendered NetworkPolicies. The script approves only its synthetic adoption
candidate and grants the exact worker Secret name; use the
[administrator workflow](../../docs/architecture/existing-keycloak-adoption.md#administrator-workflow)
for real objects. This demonstration does not measure the 30-day rotation period,
test a browser login, prove application authorization or qualify production HA.
For a real installation, follow the [chart guide](../../charts/hankoshell-operator/README.md).
