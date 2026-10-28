# OperatorHub installation

The OLM distribution is being prepared for **1.1.0** in
[#158](https://github.com/Alien6-Studio/hankoshell-operator/issues/158). It is not
yet listed on OperatorHub. Helm remains the published installation path.

The first OLM profile runs in its own namespace on Kubernetes 1.35–1.37,
Linux amd64 or arm64, with an existing Keycloak and a NetworkPolicy-enforcing
CNI. All 17 APIs remain `v1alpha1`. Lifecycle, connected Hub and experimental
provider profiles require Helm.

Local data-plane qualification uses Cilium 1.20.4 with
`policyCIDRMatchMode: [nodes]`: this lets the declared API-server `ipBlock` rules
match node addresses. Cilium excludes these addresses by default; see its
[NetworkPolicy behavior](https://docs.cilium.io/en/stable/network/kubernetes/policy/).
Verify required API/Keycloak connections and denied egress on your actual CNI.

## Prepare before subscribing

OLM cannot install the chart's ValidatingAdmissionPolicies. An administrator
must prepare the same admission and network protections before approving an
InstallPlan. Use the source matching the bundle version; do not install over
a Helm-owned operator or let two operators watch the same namespace.

1. Start from the chart's [values](../charts/hankoshell-operator/values.yaml).
   Set `keycloak.url`, `keycloak.credentialsSecret`, optional `keycloak.caSecret`,
   and exact Kubernetes API and Keycloak network destinations. Declare only
   required Secret and Deployment names under `sensitiveWrites`. Create the
   credential Secret separately with `client-id` and `client-secret` keys.
2. Render local preparation output with the **actual** Kubernetes version:

   ```sh
   make olm-install NAMESPACE=hankoshell-system VALUES=/path/to/olm-values.yaml \
     KUBERNETES_VERSION=1.37.0 OLM_OUTPUT=dist/olm-install
   ```

3. Review `dist/olm-install/installation.yaml`, then apply it to the intended
   cluster. It contains namespace Pod Security labels, admission and network
   policies, bounded RBAC, an immutable contract, OperatorGroup and Subscription.
   This local file may contain infrastructure addresses; do not commit it.
4. Review and approve the generated InstallPlan. The operator verifies live
   protection specifications against a SHA-256 approved independently in the
   Subscription. Missing policies, incomplete CEL type checking, a different
   namespace, incompatible CRD storage or a Helm installation block startup.

The verification runs before provider clients or controllers start. It is a
startup check, not a continuous admission-policy monitor or proof that the CNI
enforces traffic. Administrators retain ownership of the preparation resources.
No preparation command reads credentials or changes Keycloak.

Supply the approved Subscription configuration before approving its InstallPlan.
In the OLM 0.41.0 qualification, a CSV stalled during installation did not receive
a later environment override. The supported installation procedure supplies the
complete approval before the CSV is installed.

## Upgrade and removal

Regenerate preparation output from the new version and review the changes before
approving its InstallPlan. Changed contracts receive a new immutable ConfigMap;
the Subscription selects it and carries the new approval hash. Remove superseded
contract ConfigMaps after the rollout. Do not use Hub-driven self-update or
Helm uninstall against an OLM-owned deployment.

Removing the Subscription and CSV retains custom resources and provider objects.
Do not delete CRDs to uninstall the operator: doing so deletes their Kubernetes
objects. Resolve finalizers while a compatible operator is still running. Remove
administrator preparation resources separately when no installation uses them.

## Maintain the bundle

Generate from a clean source checkout matching the qualified image:

```sh
python3 -m tools.bootstrap.install operator_sdk --directory .tools/bin/olm
make olm-bundle IMAGE=ghcr.io/alien6-studio/hankoshell-operator@sha256:IMAGE_DIGEST \
  OPERATOR_SDK=.tools/bin/olm/operator-sdk OLM_OUTPUT=dist/olm-bundle
```

Generation takes deployment, RBAC and CRDs from `helm template`; no second
handwritten installation is maintained. Site values are rejected in public
bundles. For subsequent catalog versions, pass `REPLACES` with the preceding CSV.
The output has the community repository's `manifests`, `metadata` and `tests`
layout. Submit it under `operators/hankoshell-operator/VERSION` in
[community-operators](https://github.com/k8s-operatorhub/community-operators)
with a signed-off commit, after final-image installation and replacement tests.
Catalog acceptance and the public listing are separate upstream steps.
