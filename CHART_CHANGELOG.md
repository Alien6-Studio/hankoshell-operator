# Helm chart changelog

## 1.2.3

hankoShell Helm chart 1.2.3 ships operator 1.2.3 and its updated CRDs, including
`serviceAccountRealmRoles` on `HankoApplication`.

- The Keycloak credentials Secret is referenced as optional so the pod can be
  created before the Secret exists; a started operator still refuses to run
  without the credentials. The OLM bundle generated from this chart waits for
  the administrator approval instead of exiting.

## 1.2.2

hankoShell Helm chart 1.2.2 updates the installation and catalogue guidance for
operator 1.2.1. It uses the same published operator image.

- Install the chart version shown in the catalogue using up-to-date examples.
- Find guidance for service-account access rights, upgrades and sign-in branding.

Operator 1.2.1 makes the declared OAuth rights effective for service accounts.
Removing a right prevents new tokens from requesting it; tokens already issued
retain their rights until expiry.
