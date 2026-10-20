"""Bootstrap a disposable real server; never imported by the operator."""

import json
import os

from django.contrib.auth.models import Permission
from authentik.core.models import User, UserTypes, Token, TokenIntents
from authentik.crypto.builder import CertificateBuilder
from authentik.crypto.models import CertificateKeyPair
from authentik.flows.models import Flow, FlowDesignation
from authentik.providers.oauth2.models import ScopeMapping
from authentik.rbac.models import Role

user, _ = User.objects.get_or_create(
    username="hanko-experimental-operator",
    defaults={"name": "Disposable operator", "type": UserTypes.SERVICE_ACCOUNT})
permissions = [Permission.objects.get(codename=action + "_" + model)
               for model in ["oauth2provider", "application"]
               for action in ["add", "view", "change", "delete"]]
role, _ = Role.objects.get_or_create(name="hanko-experimental-operator")
role.assign_perms(permissions)
user.roles.set([role])
Token.objects.create(identifier="hanko-qualification", user=user,
                     intent=TokenIntents.INTENT_API, key=os.environ["HANKO_FIXTURE_TOKEN"], expiring=False)
denied, _ = User.objects.get_or_create(
    username="hanko-experimental-denied",
    defaults={"name": "Disposable denied credential", "type": UserTypes.SERVICE_ACCOUNT})
Token.objects.create(identifier="hanko-denied", user=denied,
                     intent=TokenIntents.INTENT_API, key=os.environ["HANKO_FIXTURE_DENIED_TOKEN"], expiring=False)
auth, _ = Flow.objects.get_or_create(
    slug="hanko-authorization", defaults={"name": "Qualification authorization",
                                        "title": "Qualification", "designation": FlowDesignation.AUTHORIZATION})
invalid, _ = Flow.objects.get_or_create(
    slug="hanko-invalidation", defaults={"name": "Qualification invalidation",
                                        "title": "Qualification", "designation": FlowDesignation.INVALIDATION})
builder = CertificateBuilder("hanko-qualification")
builder.build()
key = CertificateKeyPair.objects.create(name="hanko-qualification", certificate_data=builder.certificate,
                                       key_data=builder.private_key)
mapping, _ = ScopeMapping.objects.get_or_create(
    name="hanko-qualification-openid", defaults={"scope_name": "openid", "expression": "return {}"})
print("HANKO_FIXTURE_CONFIG=" + json.dumps({
    "schemaVersion": 1, "provider": "authentik", "version": "2026.8.4", "endpoint": "", "realm": "portable",
    "tokenSecret": "provider-token", "authorizationFlow": str(auth.pk), "invalidationFlow": str(invalid.pk),
    "signingKey": str(key.pk), "scopeMappings": [str(mapping.pk)]}))
