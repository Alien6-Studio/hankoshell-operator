#!/usr/bin/env bash
# Disposable demonstration of the published release; no existing kubeconfig is used.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE="$ROOT/.tools/kind-demo"
FORWARD_PID=""
MODE=up
if [[ $# -gt 0 ]]; then MODE=$1; fi
if [[ $# -gt 1 ]]; then
  echo "Usage: $0 [up|verify|down]" >&2
  exit 2
fi

die() { echo "Demo: $*" >&2; exit 1; }
step() { printf '\n%s\n' "$*"; }
k() {
  kubectl --kubeconfig "$STATE/kubeconfig" --context "kind-$CLUSTER" \
    --request-timeout=30s --namespace auth "$@"
}
finished() {
  local status=$1
  if [[ -n "$FORWARD_PID" ]]; then
    kill "$FORWARD_PID" 2>/dev/null || true
    wait "$FORWARD_PID" 2>/dev/null || true
  fi
  if [[ $status -ne 0 && -d "$STATE" ]]; then
    echo "Demo stopped. Inspect the disposable cluster, or run $0 down." >&2
  fi
}
trap 'finished $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

require() {
  local tool
  for tool in "$@"; do command -v "$tool" >/dev/null || die "Install $tool first."; done
}
read_state() {
  [[ ! -L "$STATE" && -f "$STATE/owner" ]] || die "No owned demo state found."
  [[ "$(cat "$STATE/owner")" == hankoshell-kind-demo-v1 ]] || die "Unrecognized demo state."
  CLUSTER="$(cat "$STATE/cluster")"
  [[ "$CLUSTER" =~ ^hankoshell-demo-[a-f0-9]{12}$ ]] || die "Invalid demo cluster name."
}
check_cluster() {
  read_state
  local actual
  actual="$(docker inspect --format '{{.Id}}' "$CLUSTER-control-plane")"
  [[ -s "$STATE/container-id" && "$actual" == "$(cat "$STATE/container-id")" ]] ||
    die "Cluster container changed; refusing to target it."
  [[ "$(docker inspect --format '{{index .Config.Labels "io.x-k8s.kind.cluster"}}' "$CLUSTER-control-plane")" == "$CLUSTER" ]] ||
    die "Container does not belong to this kind cluster."
  [[ -f "$STATE/kubeconfig" && ! -L "$STATE/kubeconfig" ]] || die "Missing isolated kubeconfig."
}
check_api() {
  check_cluster
  [[ -s "$STATE/namespace-uid" ]] || die "Missing cluster API identity."
  [[ "$(k get namespace kube-system -o jsonpath='{.metadata.uid}')" == "$(cat "$STATE/namespace-uid")" ]] ||
    die "Kubeconfig points to a different cluster; refusing to use it."
}
forward() {
  check_api
  kubectl --kubeconfig "$STATE/kubeconfig" --context "kind-$CLUSTER" --namespace auth \
    port-forward service/keycloak :8443 --address 127.0.0.1 >"$STATE/forward.log" 2>&1 &
  FORWARD_PID=$!
  local deadline=$((SECONDS + 30)) port=""
  while [[ $SECONDS -lt $deadline ]]; do
    port="$(sed -n 's/^Forwarding from 127.0.0.1:\([0-9]*\) ->.*/\1/p' "$STATE/forward.log" | head -1)"
    if [[ -n "$port" ]]; then ENDPOINT="https://localhost:$port"; return; fi
    kill -0 "$FORWARD_PID" 2>/dev/null || die "Keycloak port-forward stopped."
    sleep 1
  done
  die "Keycloak port-forward timed out."
}
login() {
  curl --fail --silent --show-error --cacert "$STATE/ca.crt" --connect-timeout 5 --max-time 30 \
    --data-urlencode client_id=admin-cli --data-urlencode grant_type=password \
    --data-urlencode username=demo-admin --data-urlencode "password@$STATE/admin-password" \
    "$ENDPOINT/realms/master/protocol/openid-connect/token" >"$STATE/admin-token.json"
  jq -er '"header = \"Authorization: Bearer " + .access_token + "\""' \
    "$STATE/admin-token.json" >"$STATE/admin-curl.conf"
}
api() {
  local method=$1 path=$2 status
  shift 2
  status="$(curl --silent --show-error --cacert "$STATE/ca.crt" --connect-timeout 5 --max-time 30 \
    --config "$STATE/admin-curl.conf" --request "$method" --header 'Content-Type: application/json' \
    --output "$STATE/response.json" --write-out '%{http_code}' "$ENDPOINT$path" "$@")"
  [[ "$status" =~ ^20[0-9]$ ]] || die "Keycloak $method $path returned HTTP $status."
  cat "$STATE/response.json"
}
client() {
  api GET "/admin/realms/$1/clients?clientId=$2" |
    jq -e 'if length == 1 then .[0] else error("Expected exactly one client") end'
}
identity() {
  local name=$1 secret=$2 id user role entry roles='[]'
  shift 2
  jq -n --arg name "$name" --rawfile secret "$secret" \
    '{clientId:$name,secret:$secret,enabled:true,protocol:"openid-connect",publicClient:false,
      serviceAccountsEnabled:true,standardFlowEnabled:false,directAccessGrantsEnabled:false,fullScopeAllowed:false}' \
    >"$STATE/identity.json"
  api POST /admin/realms/master/clients --data-binary "@$STATE/identity.json" >/dev/null
  id="$(client master "$name" | jq -er .id)"
  user="$(api GET "/admin/realms/master/clients/$id/service-account-user" | jq -er .id)"
  for role in "$@"; do
    entry="$(api GET "/admin/realms/master/clients/$PROXY/roles/$role")"
    roles="$(printf '%s' "$roles" | jq --argjson role "$entry" '. + [$role]')"
  done
  printf '%s\n' "$roles" >"$STATE/roles.json"
  api POST "/admin/realms/master/users/$user/role-mappings/clients/$PROXY" \
    --data-binary "@$STATE/roles.json" >/dev/null
  api POST "/admin/realms/master/clients/$id/scope-mappings/clients/$PROXY" \
    --data-binary "@$STATE/roles.json" >/dev/null
}
wait_object() {
  local label=$1 resource=$2 query=$3 deadline=$((SECONDS + 180))
  while [[ $SECONDS -lt $deadline ]]; do
    if k get "$resource" -o json >"$STATE/object.json" &&
      jq -e "$query" "$STATE/object.json" >/dev/null; then return; fi
    sleep 2
  done
  k get pods
  die "$label did not become ready within 180 seconds."
}
ready() {
  wait_object "$1" "$1" '.status.phase == "Ready" and .status.observedGeneration == .metadata.generation'
}
verify() {
  login
  ready hankoapplication/customer-portal
  client example customer-portal | jq -e \
    '.publicClient and .protocol == "openid-connect" and .redirectUris == ["https://portal.example.com/callback"]' >/dev/null
  echo "PASS: OIDC SPA client and callback are reconciled in Keycloak."

  ready hankoapplication/existing-portal
  client example existing-portal >"$STATE/existing-after.json"
  [[ "$(jq -r .id "$STATE/existing-after.json")" == "$(cat "$STATE/existing-id")" ]] ||
    die "Adoption changed the existing client UUID."
  k get hankoapplication existing-portal -o json |
    jq -e '.spec.mode == "Manage" and .status.adoptionReceipt.state == "Verified"' >/dev/null
  echo "PASS: the existing client is explicitly adopted and managed with the same UUID."

  ready hankoserviceaccount/report-worker
  k get secret hanko-sa-report-worker -o json |
    jq -r '.data.client_secret | @base64d' | tr -d '\n' >"$STATE/worker-secret"
  curl --fail --silent --show-error --cacert "$STATE/ca.crt" --connect-timeout 5 --max-time 30 \
    --data-urlencode client_id=report-worker --data-urlencode grant_type=client_credentials \
    --data-urlencode "client_secret@$STATE/worker-secret" \
    "$ENDPOINT/realms/example/protocol/openid-connect/token" >"$STATE/worker-token.json"
  jq -e '.token_type == "Bearer" and (.access_token | length > 0) and .expires_in > 0' \
    "$STATE/worker-token.json" >/dev/null
  echo "PASS: the machine client obtains a real OAuth client_credentials token."
  k get hankoapplication,hankoserviceaccount
}
up() {
  [[ ! -e "$STATE" && ! -L "$STATE" ]] || die "Demo state already exists; run $0 down before starting again."
  local release node_image keycloak_image image service endpoint
  release="$(jq -er .release.version "$ROOT/versions.json")"
  node_image="$(jq -er '.kubernetes.node_images[.kubernetes.default]' "$ROOT/versions.json")"
  keycloak_image="$(jq -er '.keycloak.images[.keycloak.default]' "$ROOT/versions.json")"
  [[ "$release" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "A published stable version is required."
  mkdir -p "$STATE"
  printf 'hankoshell-kind-demo-v1\n' >"$STATE/owner"
  CLUSTER="hankoshell-demo-$(openssl rand -hex 6)"
  printf '%s\n' "$CLUSTER" >"$STATE/cluster"
  export KUBECONFIG="$STATE/kubeconfig"

  step "1/5: create an isolated kind cluster"
  if ! kind create cluster --name "$CLUSTER" --image "$node_image" --kubeconfig "$STATE/kubeconfig" --wait 120s; then
    docker inspect --format '{{.Id}}' "$CLUSTER-control-plane" >"$STATE/container-id" 2>/dev/null || true
    die "kind cluster creation failed."
  fi
  docker inspect --format '{{.Id}}' "$CLUSTER-control-plane" >"$STATE/container-id"
  check_cluster
  k get namespace kube-system -o jsonpath='{.metadata.uid}' >"$STATE/namespace-uid"
  k create namespace auth
  k label namespace auth pod-security.kubernetes.io/enforce=restricted
  openssl rand -hex 32 | tr -d '\n' >"$STATE/admin-password"
  openssl rand -hex 32 | tr -d '\n' >"$STATE/operator-secret"
  openssl rand -hex 32 | tr -d '\n' >"$STATE/inventory-secret"
  openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -keyout "$STATE/tls.key" -out "$STATE/ca.crt" -subj /CN=keycloak.auth.svc \
    -addext 'subjectAltName=DNS:keycloak.auth.svc,DNS:localhost' \
    -addext 'basicConstraints=critical,CA:true' 2>"$STATE/certificate.log"
  k create secret generic keycloak-bootstrap --from-file="password=$STATE/admin-password"
  k create secret tls keycloak-tls --cert "$STATE/ca.crt" --key "$STATE/tls.key"
  k create secret generic operator-ca --from-file="ca.crt=$STATE/ca.crt"
  sed "s|KEYCLOAK_IMAGE|$keycloak_image|" "$ROOT/examples/kind/keycloak.yaml" | k apply -f -
  k rollout status deployment/keycloak --timeout=240s
  forward
  login

  step "2/5: prepare a test realm, scoped writer and read-only observer"
  api POST /admin/realms --data-binary '{"realm":"example","enabled":true}' >/dev/null
  PROXY="$(client master example-realm | jq -er .id)"
  identity demo-operator "$STATE/operator-secret" manage-realm manage-clients manage-events
  identity demo-inventory "$STATE/inventory-secret" view-realm view-clients
  k create secret generic operator-credentials --from-literal=client-id=demo-operator \
    --from-file="client-secret=$STATE/operator-secret"
  printf 'https://keycloak.auth.svc:8443' >"$STATE/provider-url"
  k create secret generic inventory-credentials --from-file="HANKO_KEYCLOAK_URL=$STATE/provider-url" \
    --from-literal=HANKO_KC_CLIENT_ID=demo-inventory --from-file="HANKO_KC_CLIENT_SECRET=$STATE/inventory-secret"
  api POST /admin/realms/example/clients --data-binary '{
    "clientId":"existing-portal","name":"existing-portal","protocol":"openid-connect","enabled":true,
    "publicClient":true,"standardFlowEnabled":true,"directAccessGrantsEnabled":false,
    "serviceAccountsEnabled":false,"implicitFlowEnabled":false,"fullScopeAllowed":false,
    "redirectUris":["https://existing.example.com/callback"],"webOrigins":["+"],
    "defaultClientScopes":[],"optionalClientScopes":[],
    "attributes":{"realm_client":"false","backchannel.logout.session.required":"true",
      "backchannel.logout.revoke.offline.tokens":"false"}}' >/dev/null
  client example existing-portal >"$STATE/existing-before.json"
  jq -er .id "$STATE/existing-before.json" >"$STATE/existing-id"

  step "3/5: install the published Helm chart and digest-pinned operator image"
  curl --fail --silent --show-error --location --connect-timeout 10 --max-time 60 \
    "https://github.com/Alien6-Studio/hankoshell-operator/releases/download/v$release/image-digest.txt" >"$STATE/image.txt"
  image="$(tr -d '\r\n' <"$STATE/image.txt")"
  [[ "$image" =~ ^ghcr.io/alien6-studio/hankoshell-operator@sha256:[a-f0-9]{64}$ ]] ||
    die "Release does not identify the expected immutable public operator image."
  service="$(k get service kubernetes -n default -o jsonpath='{.spec.clusterIP}')"
  endpoint="$(k get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o json |
    jq -er '.items[0].endpoints[0].addresses[0]')"
  jq -n --arg digest "$(printf '%s' "$image" | cut -d@ -f2)" --arg service "$service/32" --arg endpoint "$endpoint/32" \
    '{fullnameOverride:"demo-operator",image:{digest:$digest},
      keycloak:{url:"https://keycloak.auth.svc:8443",credentialsSecret:"operator-credentials",caSecret:"operator-ca"},
      networkPolicy:{kubernetesAPIServiceCIDRs:[$service],kubernetesAPIEndpointCIDRs:[$endpoint]},
      sensitiveWrites:{secrets:["hanko-sa-report-worker"]},resources:{limits:{cpu:"1",memory:"256Mi"}}}' >"$STATE/values.json"
  helm install demo oci://ghcr.io/alien6-studio/charts/hankoshell-operator --version "$release" \
    --kubeconfig "$STATE/kubeconfig" --kube-context "kind-$CLUSTER" --namespace auth \
    --values "$STATE/values.json" --wait --timeout 180s
  k apply -f "$ROOT/examples/kind/identities.yaml"

  step "4/5: approve only the freshly observed synthetic client, then enable management"
  login
  wait_object "approvable adoption candidate" hankoapplication/existing-portal \
    '.status.adoptionCandidate | .complete == true and .truncated == false and .approvable == true'
  client example existing-portal | jq -S . >"$STATE/existing-observed.json"
  jq -S . "$STATE/existing-before.json" | cmp -s - "$STATE/existing-observed.json" ||
    die "Observe changed the existing client."
  k get hankoapplication existing-portal -o json >"$STATE/candidate.json"
  jq -e --arg id "$(cat "$STATE/existing-id")" \
    '.status.adoptionCandidate.providerIdentity.objectIDs | index($id) != null' "$STATE/candidate.json" >/dev/null
  k annotate hankoapplication existing-portal \
    hanko.sh/adoption-contract=hanko.sh/adoption-contract/v1alpha1 \
    "hanko.sh/adoption-candidate=$(jq -er .status.adoptionCandidate.candidateHash "$STATE/candidate.json")"
  wait_object "verified adoption receipt" hankoapplication/existing-portal '.status.adoptionReceipt.state == "Verified"'
  client example existing-portal | jq -S \
    'del(.access, .attributes["hanko.sh/application-owner"], .attributes["hanko.sh/adoption-receipt"])' >"$STATE/existing-acquired.json"
  jq -S 'del(.access)' "$STATE/existing-before.json" | cmp -s - "$STATE/existing-acquired.json" ||
    die "Acquisition changed more than the client's ownership metadata."
  k patch hankoapplication existing-portal --type merge --patch '{"spec":{"mode":"Manage"}}'
  k annotate hankoapplication existing-portal hanko.sh/adoption-source- \
    hanko.sh/adoption-contract- hanko.sh/adoption-candidate-

  step "5/5: verify real provider state and machine authentication"
  verify
  printf '\nDemo is ready. Private state: %s\n' "$STATE"
  printf 'Inspect: kubectl --kubeconfig "%s/kubeconfig" -n auth get hankoapplication,hankoserviceaccount\n' "$STATE"
  printf 'Clean up: %s down\n' "$0"
}
down() {
  if [[ ! -e "$STATE" && ! -L "$STATE" ]]; then echo "No demo to remove."; return; fi
  read_state
  if docker inspect "$CLUSTER-control-plane" >/dev/null 2>&1; then
    check_cluster
    kind delete cluster --name "$CLUSTER" --kubeconfig "$STATE/kubeconfig"
  else
    [[ -f "$STATE/container-id" ]] || die "Creation was interrupted before ownership was recorded; inspect the named kind cluster."
  fi
  rm -rf -- "$STATE"
  echo "Demo cluster and private state removed."
}

case "$MODE" in
  up|verify) require docker kind kubectl helm openssl curl jq cmp; ;;
  down) require docker kind; ;;
  *) die "Usage: $0 [up|verify|down]"; ;;
esac
docker info >/dev/null
case "$MODE" in
  up) up ;;
  verify) check_cluster; forward; verify ;;
  down) down ;;
esac
