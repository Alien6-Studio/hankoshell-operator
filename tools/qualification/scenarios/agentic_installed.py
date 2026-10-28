"""A2A 1.0 to bounded native exchange to MCP and an independent backend token."""
import copy
import hashlib
import json
from pathlib import Path
import statistics
import secrets
import subprocess
import time

import yaml

ROOT = Path(__file__).resolve().parents[3]
BASE = "https://delegation-resource.auth.svc:8445"


def qualify(fixture, wait):
    manifests = list(yaml.safe_load_all((ROOT / "examples/agent-authority/identities.yaml").read_text()))
    for value in manifests:
        value["metadata"]["namespace"] = "auth"
        if value["kind"] != "HankoResourceServer":
            fixture.apply_approved(value)
            resource = value["kind"].lower()
            wait("agent software identity", lambda value=value, resource=resource: fixture.ready(resource, value["metadata"]["name"]), 180)
    for value in manifests:
        if value["kind"] == "HankoResourceServer":
            fixture.apply(value)
            wait("distinct protected agent audience", lambda value=value: fixture.iam_reconciled("hankoresourceserver", value["metadata"]["name"]), 180)

    def native_resource(client, name):
        values = fixture.api("GET", f'/admin/realms/managed/clients/{client["id"]}/authz/resource-server/resource')
        matches = [value for value in values if value.get("name") == name]
        if len(matches) != 1:
            raise ValueError("Agent fixture native resource read-back ambiguous")
        return matches[0].get("_id") or matches[0]["id"]

    ingress, mcp, backend = (fixture.client("managed", name) for name in ("agent-b-ingress", "agent-mcp-api", "agent-business-api"))
    actor, subject = (fixture.client("managed", name) for name in ("agent-b", "agent-a"))
    actor_user, subject_user = (fixture.api("GET", f'/admin/realms/managed/clients/{client["id"]}/service-account-user')["id"]
                               for client in (actor, subject))
    document = json.loads(mcp.get("attributes", {})["oauth.bounded-delegation.v1"])
    if document.get("phase") != "Committed":
        raise ValueError("Agent grant is not committed")
    settings = {"issuer": fixture.provider_url + "/realms/managed", "audience": "agent-mcp-api",
                "resources": {"/allowed": native_resource(mcp, "invoice"), "/denied": native_resource(mcp, "foreign-invoice")},
                "agentic": {"a2aAudience": "agent-b-ingress", "a2aResource": native_resource(ingress, "tasks"),
                    "downstreamAudience": "agent-business-api", "downstreamResource": native_resource(backend, "invoice"),
                    "actorClient": "agent-b", "actorSubject": actor_user, "subjectClient": "agent-a", "subjectSubject": subject_user,
                    "actorCredentials": "/fixture/actor.json", "subjectCredentials": "/fixture/subject.json",
                    "publicURL": BASE, "resourceName": "invoice", "policyRevision": hashlib.sha256(mcp["attributes"]["oauth.bounded-delegation.v1"].encode()).hexdigest()}}
    config = fixture.get("configmap", "delegation-resource")
    config["data"].update({"settings.json": json.dumps(settings),
        "actor.json": json.dumps({"client_id": "agent-b", "client_secret_path": "/actor/client_secret"}),
        "subject.json": json.dumps({"client_id": "agent-a", "client_secret_path": "/subject/client_secret"})})
    pod = fixture.get("pod", "delegation-resource")
    spec = copy.deepcopy(pod["spec"])
    for name, client in (("actor", "agent-b"), ("subject", "agent-a")):
        # Capture only in private driver memory for the existing leak detector.
        fixture.secret_value(client)
        spec["volumes"].append({"name": name, "secret": {"secretName": "hanko-sa-" + client, "defaultMode": 288}})
        spec["containers"][0]["volumeMounts"].append({"name": name, "mountPath": "/" + name, "readOnly": True})
    def restart_fixture(probe_case=""):
        settings["agentic"]["qualificationProbe"] = probe_case
        config["data"]["settings.json"] = json.dumps(settings)
        fixture.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "delegation-resource", "namespace": "auth"}, "data": config["data"]})
        fixture.kubectl("delete", "pod", "delegation-resource", "-n", "auth", "--wait=true")
        fixture.apply({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "delegation-resource", "namespace": "auth", "labels": {"app": "delegation-resource"}}, "spec": spec})
        fixture.kubectl("wait", "--for=condition=Ready", "pod/delegation-resource", "-n", "auth", "--timeout=180s")

    restart_fixture()

    def probe(action, **private):
        anchor = fixture.workload_anchors["delegation-actor"]
        settings = {"action": action, "issuer": fixture.provider_url + "/realms/managed", **private}
        script = (ROOT / "tools/qualification/fixtures/agentic_pod_probe.py").read_text()
        wrapper = "import sys,io\nsys.stdin=io.StringIO(" + repr(json.dumps(settings)) + ")\n" + script
        command = [str(fixture.args.kubectl), "--kubeconfig", str(fixture.config), "exec", "-i", "-n", "workload", anchor["pod"], "--", "python", "-"]
        result = subprocess.run(command, input=wrapper.encode(), capture_output=True, timeout=60, check=False)
        if result.returncode or len(result.stdout) > 65536:
            raise ValueError("Private agent protocol probe failed")
        value = json.loads(result.stdout)
        if value.get("probe_failed"):
            raise ValueError("Private agent protocol probe refused inputs")
        if value.get("access_token"):
            fixture.sensitive.append(value["access_token"])
        return value

    def input_token(client, audience, permission):
        value = probe("input", client=client, audience=audience, permissions=[permission], private_secret=fixture.secret_value(client))
        if value.get("http_status") != 200 or not value.get("access_token"):
            raise ValueError("Native agent input unavailable")
        return value["access_token"]

    untrusted_trace = "f" * 32
    headers = {"A2A-Version": "1.0", "traceparent": "00-" + untrusted_trace + "-" + "e" * 16 + "-01"}
    body = {"message": {"messageId": "synthetic-message", "role": "ROLE_USER", "parts": [{"text": "Read the synthetic invoice"}]}}
    sender = input_token("agent-a", "agent-b-ingress", "tasks#invoke")
    def invoke():
        body["message"]["messageId"] = secrets.token_hex(16)
        return probe("request", endpoint=BASE + "/message:send", bearer=input_token("agent-a", "agent-b-ingress", "tasks#invoke"), headers=headers, body=body)

    def traces():
        logs = fixture.kubectl("logs", "delegation-resource", "-n", "auth", "--tail=500")
        records = []
        for line in logs.splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if value.get("schema") == 1 and value.get("stage"):
                if set(value) - {"schema", "time", "trace_id", "span_id", "parent_span_id", "stage", "decision", "policy_revision", "actor_ref", "subject_ref", "audience_ref", "coverage"}:
                    raise ValueError("Agent telemetry exceeded its privacy allowlist")
                records.append(value)
        fixture.record("untrusted_trace_parent_is_not_authority", all(value["trace_id"] != untrusted_trace for value in records))
        return records
    measurements = []
    exchange_measurements = []
    for _ in range(3):
        body["message"]["messageId"] = secrets.token_hex(16)
        result = probe("request", endpoint=BASE + "/message:send", bearer=sender, headers=headers, body=body)
        fixture.record("a2a_native_exchange_mcp_backend_allowed", result["http_status"] == 200 and result["completed"] is True)
        measurements.append(result["elapsed_ms"])
        exchange = probe("exchange", client="agent-b", audience="agent-mcp-api",
                         actor=input_token("agent-b", "agent-mcp-api", "invoice#read"),
                         subject=input_token("agent-a", "agent-mcp-api", "invoice#read"),
                         private_secret=fixture.secret_value("agent-b"))
        fixture.record("fresh_native_exchange_latency_sample_issued", exchange["http_status"] == 200 and exchange["issued"])
        exchange_measurements.append(exchange["elapsed_ms"])
    observed = traces()
    completed_traces = {value["trace_id"] for value in observed if value["stage"] == "task" and value["decision"] == "allow"}
    fixture.record("each_success_has_a_complete_trace", len(completed_traces) == 3)
    for trace in completed_traces:
        chain = [value for value in observed if value["trace_id"] == trace]
        fixture.record("a2a_exchange_mcp_backend_otlp_correlate", {value["stage"] for value in chain} == {"a2a", "exchange", "mcp", "downstream", "task"}
                       and all(value["coverage"] == "exported" for value in chain))
    for name, changed in (("caller_task_id", {**body, "message": {**body["message"], "taskId": "untrusted-task"}}),
                           ("agent_card_not_authority", {**body, "agentCard": {"scope": "write"}})):
        result = probe("request", endpoint=BASE + "/message:send", bearer=sender, headers=headers, body=changed)
        fixture.record(name, result["http_status"] == 400 and result["completed"] is False)
    mcp_input = input_token("agent-b", "agent-mcp-api", "invoice#read")
    rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_invoice", "arguments": {}}}
    for name, bearer, endpoint, payload, extra, method in (
        ("a2a_token_at_mcp_refused", sender, "/mcp", rpc, {"MCP-Protocol-Version": "2025-11-25"}, None),
        ("mcp_direct_gateway_bypass_refused", mcp_input, "/mcp", rpc, {"MCP-Protocol-Version": "2025-11-25"}, None),
        ("mcp_token_passthrough_to_backend_refused", mcp_input, "/downstream", None, {}, "GET"),
        ("mcp_token_at_a2a_refused", mcp_input, "/message:send", body, headers, None),
    ):
        result = probe("request", endpoint=BASE + endpoint, bearer=bearer, body=payload, headers=extra, method=method)
        fixture.record(name, result["http_status"] in (401, 403) and not result["completed"])

    for case in ("wrong-tool", "wrong-scope", "foreign-resource", "missing-gateway", "foreign-task", "spent-task"):
        restart_fixture(case)
        result = invoke()
        fixture.record("real_mcp_" + case.replace("-", "_") + "_refused", result["http_status"] == 403 and not result["completed"])
        events = traces()
        fixture.record("real_mcp_denial_is_audited_" + case.replace("-", "_"), any(value["stage"] == "mcp" and value["decision"] == "deny" for value in events))
        if case == "spent-task":
            fixture.record("mcp_task_is_exercised_once", sum(value["stage"] == "downstream" and value["decision"] == "allow" for value in events) == 1)

    restart_fixture()
    mcp_input = input_token("agent-b", "agent-mcp-api", "invoice#read")
    child = probe("request", endpoint=BASE + "/mcp", bearer=mcp_input, body=rpc,
                  headers={"MCP-Protocol-Version": "2025-11-25", "traceparent": headers["traceparent"], "X-Fixture-Task": "parent-task-is-not-authority"}, fork=True)
    fixture.record("forked_child_cannot_inherit_gateway_authority", child["http_status"] == 403 and not child["completed"])
    fixture.record("forked_child_is_a_separate_untrusted_trace", bool(traces()) and all(value["trace_id"] != untrusted_trace for value in traces()))
    fixture.report["child_execution_coverage"] = "incomplete: independently forked bypass client observed; no general child-agent execution instrumentation"

    restart_fixture("collector-outage")
    result = invoke()
    events = traces()
    fixture.record("collector_loss_is_visible_and_does_not_grant", result["http_status"] == 503 and any(value["coverage"] == "incomplete" for value in events)
                   and not any(value["stage"] in ("exchange", "downstream") and value["decision"] == "allow" for value in events))

    original = fixture.get("hankoresourceserver", "agent-mcp-api")["spec"]
    short = copy.deepcopy(original)
    next(value for value in short["permissions"] if value.get("delegation"))["delegation"]["maxTTLSeconds"] = 2
    fixture.patch("hankoresourceserver", "agent-mcp-api", {"spec": short})
    wait("short native agent grant", lambda: fixture.iam_reconciled("hankoresourceserver", "agent-mcp-api"), 180)
    current = fixture.client("managed", "agent-mcp-api")
    current_document = json.loads(current["attributes"]["oauth.bounded-delegation.v1"])
    fixture.record("short_agent_grant_read_back", all(value["maxTTLSeconds"] == 2 for value in current_document["grants"]))
    settings["agentic"]["policyRevision"] = hashlib.sha256(fixture.client("managed", "agent-mcp-api")["attributes"]["oauth.bounded-delegation.v1"].encode()).hexdigest()
    restart_fixture("expired")
    result = invoke()
    fixture.record("real_expired_mcp_token_refused", result["http_status"] == 403 and not result["completed"])
    fixture.patch("hankoresourceserver", "agent-mcp-api", {"spec": original})
    wait("restored native agent grant", lambda: fixture.iam_reconciled("hankoresourceserver", "agent-mcp-api"), 180)
    current_document = json.loads(fixture.client("managed", "agent-mcp-api")["attributes"]["oauth.bounded-delegation.v1"])
    settings["agentic"]["policyRevision"] = hashlib.sha256(fixture.client("managed", "agent-mcp-api")["attributes"]["oauth.bounded-delegation.v1"].encode()).hexdigest()
    restart_fixture()
    fixture.record("trusted_adapter_restart_uses_fresh_evidence", invoke()["completed"] is True)

    def exchange_faults(profile):
        # The proxy sees the broker's socket peer, independently of request headers.
        # Minting the A2A caller token happens in another pod and remains available.
        peer = fixture.get("pod", "delegation-resource")["status"]["podIP"]
        for action in ("deny", "lost-ack"):
            fixture.control("keycloak", {"method": "POST", "path": "/realms/managed/protocol/openid-connect/token",
                            "oauth_grant": "urn:ietf:params:oauth:grant-type:token-exchange", "client_ip": peer, "action": action}, reset=True)
            try:
                result = invoke()
                state = fixture.await_fault("keycloak")
                fixture.record(profile + "_agent_exchange_" + action.replace("-", "_") + "_fails_closed",
                               result["http_status"] == 403 and not result["completed"] and state["fault_matches"] == 1)
                if action == "lost-ack":
                    fixture.record(profile + "_agent_lost_response_was_accepted_once", state["upstream_status"] == 200)
            finally:
                fixture.control("keycloak", None)
            fixture.record(profile + "_agent_fresh_task_recovers_after_" + action.replace("-", "_"), invoke()["completed"] is True)


    exchange_faults("software")

    # Task authorization is opt-in. The trusted issuer and recipient have
    # separate credentials; neither identity is selected from an A2A payload.
    authority = {"apiVersion": "hanko.sh/v1alpha1", "kind": "HankoServiceAccount", "metadata": {"name": "task-authority", "namespace": "auth"},
                 "spec": {"realmRef": "managed", "clientID": "task-authority", "authentication": {"mode": "Secret"}}}
    fixture.apply_approved(authority)
    wait("trusted task authority", lambda: fixture.ready("hankoserviceaccount", "task-authority"), 180)
    authority_native = fixture.client("managed", "task-authority")
    for client in (authority_native, fixture.client("managed", "agent-mcp-api")):
        fixture.api("POST", f'/admin/realms/managed/clients/{client["id"]}/protocol-mappers/models',
                    {"name": "qualification-task-endpoint", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                     "config": {"included.custom.audience": "bounded-delegation-task-context", "access.token.claim": "true"}})
    native_realm = fixture.api("GET", "/admin/realms/managed")
    task_attributes = {"oauth.bounded-delegation.task.profile": "task-bound-software",
                       "oauth.bounded-delegation.task.issuer": json.dumps({"id": authority_native["id"], "attribute": "@keycloak.client.uuid", "value": authority_native["id"]})}
    fixture.api("PUT", "/admin/realms/managed", {"attributes": {**native_realm.get("attributes", {}), **task_attributes}})
    capability = fixture.api("GET", "/realms/managed/bounded-delegation/task-context")
    fixture.record("native_task_capability_is_explicit", capability.get("enabled") is True and capability.get("stateStore") == "database"
                   and capability.get("contract") == "bounded-delegation/task-reference-v1")
    fixture.apply({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "agent-task-recipient", "namespace": "auth"},
                   "stringData": {"client_secret": fixture.native_secret("agent-mcp-api")}})
    fixture.secret_value("task-authority")
    config["data"].update({"task-authority.json": json.dumps({"client_id": "task-authority", "client_secret_path": "/authority/client_secret"}),
                           "task-recipient.json": json.dumps({"client_id": "agent-mcp-api", "client_secret_path": "/recipient/client_secret"})})
    for name, secret_name in (("authority", "hanko-sa-task-authority"), ("recipient", "agent-task-recipient")):
        spec["volumes"].append({"name": name, "secret": {"secretName": secret_name, "defaultMode": 288}})
        spec["containers"][0]["volumeMounts"].append({"name": name, "mountPath": "/" + name, "readOnly": True})
    task_spec = copy.deepcopy(original)
    next(value for value in task_spec["permissions"] if value.get("delegation"))["delegation"]["taskAuthorization"] = "required"
    fixture.patch("hankoresourceserver", "agent-mcp-api", {"spec": task_spec})
    wait("issuer-controlled task grant", lambda: fixture.iam_reconciled("hankoresourceserver", "agent-mcp-api"), 180)
    raw_document = fixture.client("managed", "agent-mcp-api")["attributes"]["oauth.bounded-delegation.v1"]
    task_document = json.loads(raw_document)
    fixture.record("task_intent_has_legacy_refusal_wire_guard", task_document["version"] == 2 and task_document["profile"] == "task-bound-software")
    settings["agentic"]["policyRevision"] = hashlib.sha256(raw_document.encode()).hexdigest()
    settings["agentic"]["taskAuthorization"] = {"authorityClient": "task-authority", "authorityCredentials": "/fixture/task-authority.json",
                                               "recipientCredentials": "/fixture/task-recipient.json", "audienceID": mcp["id"], "grant": "delegated-read"}
    restart_fixture()
    fixture.record("task_bound_a2a_native_mcp_online_read_allowed", invoke()["completed"] is True)
    exchange_faults("task")
    for case in ("invalid-approval", "approval-replay", "cancelled-task"):
        restart_fixture(case)
        result = invoke()
        fixture.record("native_task_" + case.replace("-", "_") + "_refused", result["http_status"] == 403 and not result["completed"])
        fixture.record("native_task_refusal_has_no_backend_effect_" + case.replace("-", "_"),
                       not any(value["stage"] == "downstream" and value["decision"] == "allow" for value in traces()))
    restart_fixture()
    peer = fixture.get("pod", "delegation-resource")["status"]["podIP"]
    fixture.control("keycloak", {"method": "POST", "path": "/realms/managed/bounded-delegation/task-context/check", "client_ip": peer, "action": "deny"}, reset=True)
    try:
        result = invoke()
        fixture.await_fault("keycloak")
        fixture.record("online_task_authority_outage_denies_operation", result["http_status"] == 403 and not result["completed"])
        fixture.record("online_task_authority_outage_has_no_backend_effect", not any(value["stage"] == "downstream" and value["decision"] == "allow" for value in traces()))
    finally:
        fixture.control("keycloak", None)
    fixture.record("online_task_authority_recovers_with_fresh_inputs", invoke()["completed"] is True)
    # Revoke the task grant, retain actor guards, and wait the old maximum lifetime
    # before demonstrating an explicit opt-out. No parser rewrites old documents.
    withdrawn = copy.deepcopy(task_spec)
    withdrawn["permissions"] = [value for value in withdrawn["permissions"] if not value.get("delegation")]
    fixture.patch("hankoresourceserver", "agent-mcp-api", {"spec": withdrawn})
    wait("withdrawn task delegation", lambda: fixture.iam_reconciled("hankoresourceserver", "agent-mcp-api"), 180)
    restart_fixture()
    result = invoke()
    fixture.record("withdrawn_agent_task_grant_stops_new_issuance", result["http_status"] == 403 and not result["completed"])
    time.sleep(32)
    fixture.patch("hankoresourceserver", "agent-mcp-api", {"spec": original})
    wait("explicit software delegation rollback", lambda: fixture.iam_reconciled("hankoresourceserver", "agent-mcp-api"), 180)
    raw_document = fixture.client("managed", "agent-mcp-api")["attributes"]["oauth.bounded-delegation.v1"]
    fixture.record("software_delegation_rollback_retains_original_wire", json.loads(raw_document)["version"] == 1 and "profile" not in json.loads(raw_document))
    settings["agentic"]["policyRevision"] = hashlib.sha256(raw_document.encode()).hexdigest()
    settings["agentic"].pop("taskAuthorization")
    restart_fixture()
    fixture.record("software_delegation_survives_task_opt_out", invoke()["completed"] is True)

    # Recreate the actual software CR only after withdrawing its delegation.
    # Old signed input evidence must not follow the reusable Kubernetes name.
    old_actor = input_token("agent-b", "agent-mcp-api", "invoice#read")
    old_identity = fixture.get("hankoserviceaccount", "agent-b")["metadata"]["uid"]
    old_client = fixture.client("managed", "agent-b")["id"]
    fixture.patch("hankoresourceserver", "agent-mcp-api", {"spec": withdrawn})
    wait("withdrawal before identity recreation", lambda: fixture.iam_reconciled("hankoresourceserver", "agent-mcp-api"), 180)
    fixture.kubectl("delete", "hankoserviceaccount", "agent-b", "-n", "auth", "--wait=true", "--timeout=180s")
    replacement = next(copy.deepcopy(value) for value in manifests if value["kind"] == "HankoServiceAccount" and value["metadata"]["name"] == "agent-b")
    fixture.apply_approved(replacement)
    wait("recreated agent software identity", lambda: fixture.ready("hankoserviceaccount", "agent-b"), 180)
    current_actor = fixture.client("managed", "agent-b")
    fixture.record("same_agent_name_has_new_kubernetes_and_native_identities",
                   fixture.get("hankoserviceaccount", "agent-b")["metadata"]["uid"] != old_identity and current_actor["id"] != old_client)
    fixture.patch("hankoresourceserver", "agent-mcp-api", {"spec": original})
    for name in ("agent-mcp-api", "agent-business-api"):
        wait("current recreated agent authorization", lambda name=name: fixture.iam_reconciled("hankoresourceserver", name), 180)
    refused = probe("exchange", client="agent-b", audience="agent-mcp-api", actor=old_actor,
                    subject=input_token("agent-a", "agent-mcp-api", "invoice#read"), private_secret=fixture.secret_value("agent-b"))
    fixture.record("recreated_agent_cannot_reuse_old_signed_input", 400 <= refused["http_status"] < 500 and not refused["issued"])
    settings["agentic"]["actorSubject"] = fixture.api("GET", f'/admin/realms/managed/clients/{current_actor["id"]}/service-account-user')["id"]
    raw_document = fixture.client("managed", "agent-mcp-api")["attributes"]["oauth.bounded-delegation.v1"]
    settings["agentic"]["policyRevision"] = hashlib.sha256(raw_document.encode()).hexdigest()
    restart_fixture()
    fixture.record("fresh_agent_evidence_works_after_explicit_rebind", invoke()["completed"] is True)

    if fixture.ha_only:
        fixture.agentic_leader_turnover()
        fixture.record("agent_flow_survives_actual_operator_leader_turnover", invoke()["completed"] is True)
    fixture.stop_operator()
    fixture.record("operator_is_not_a_runtime_token_broker", invoke()["completed"] is True)
    fixture.start_operator()
    fixture.record("agent_flow_recovers_after_operator_restart", invoke()["completed"] is True)
    fixture.report["agentic"] = {"a2a": "1.0", "mcp": "2025-11-25", "profile": "software-v1", "task_bound_jwt": True, "profiles": ["software-v1", "task-bound-software"],
        "samples": len(measurements), "e2e_ms": {"p50": statistics.median(measurements), "p95": max(measurements)},
        "exchange_samples": len(exchange_measurements),
        "exchange_ms": {"p50": statistics.median(exchange_measurements), "p95": max(exchange_measurements)},
        "audiences": 3, "telemetry": "OTLP JSON over verified TLS; process-local test sink; allowlisted decision spans",
        "limitations": ["three sequential synthetic samples are not load qualification", "single Keycloak node", "gateway-local task records", "no production collector or child-agent execution coverage claim"]}
