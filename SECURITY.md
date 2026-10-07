# Security policy

See the [deployment requirements and trust model](docs/secure-deployment.md)
for runtime boundaries, token-derived Hub HMAC authentication and response limits.

## Supported versions

Security fixes target the latest patch release in the latest published `0.x`
minor series, and its matching Helm chart. Upgrade to that patch release to
receive fixes. Older minor series, prereleases, development builds and forks
receive no separate security backports. No long-term support branch is available.

Kubernetes **1.35–1.37** is the current qualification window. Use the latest
provider security patch within it; an end-of-life or provider-extended version
does not receive additional project qualification. See the
[Kubernetes compatibility and hardening matrix](docs/secure-deployment.md#kubernetes-compatibility-and-hardening).

The project is in initial development; public APIs may change between minor
versions before `1.0.0`. Reports against `main` are welcome, but use a tagged
release for deployments.

## Report a vulnerability

Use GitHub's [private vulnerability reporting form](https://github.com/Alien6-Studio/hankoshell-operator/security/advisories/new).
If the form is unavailable, email [contact@alien6.com](mailto:contact@alien6.com)
with the subject `hankoShell Operator security report` to request a secure
reporting channel before sharing sensitive details. Do not disclose
vulnerabilities in public issues or discussions.

Include the affected version or revision, deployment configuration, impact,
reproduction steps and a minimal proof of concept using synthetic data.
Do not include live credentials, private keys or customer data.

## Response and coordinated disclosure

We aim to acknowledge reports within **2 business days**, provide an initial
assessment within **7 business days**, and update accepted reports at least
every **7 calendar days** until resolution. These are maintenance targets,
not a contractual response SLA.

Confirmed reports are prioritized by severity and exposure. We agree a fix,
mitigation and disclosure schedule with the reporter after triage; there is
no universal remediation deadline. We publish an advisory with affected and
fixed versions when a fix or mitigation is available, and credit reporters
with their consent. Please coordinate disclosure so users can apply it first.
