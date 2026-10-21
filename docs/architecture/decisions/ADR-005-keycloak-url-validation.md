# ADR-005: Keycloak URL validation and metadata endpoint exclusion

Status: Accepted

## Context

Administrative connections carry credentials to a configured Keycloak endpoint.
Malformed URLs, credential-bearing URLs and cloud metadata destinations can turn
configuration access into unsafe outbound requests. Legitimate installations may
also use private networks and custom CA roots.

## Decision

Validate an HTTP(S) origin with an optional plain context path. Reject userinfo,
queries, fragments, invalid ports, ambiguous encodings and dot segments before
administrative connection setup. Instance URL validation additionally rejects
literal metadata addresses `169.254.169.254`, `fd00:ec2::254` and `100.100.100.200`
using parsed IP equality.

The client transport requires verified HTTPS by default. Plain HTTP needs the
administrator's explicit compatibility opt-in and is forbidden by the enterprise
profile; a custom CA bundle requires HTTPS. Accepting HTTP syntax in the instance
helper is not authorization to send credentials over HTTP. Reject invalid
endpoint syntax without echoing potentially secret URL contents.

## Consequences

These checks constrain syntax, transport and literal metadata targets; they are
not a DNS-resolution or general SSRF firewall. Private addresses remain possible.
The inherited proposal for namespace DNS enforcement and a bypass allowlist is
not implemented and is not an accepted runtime guarantee here. Protect endpoint
and Secret configuration and restrict egress to reviewed destinations. DNS
resolution to metadata, rebinding and arbitrary internal destinations are not
proved safe by these literal checks. Deployment network controls remain separate.

## Enforcement

- [Instance validation and client construction](../../../internal/controller/helpers.go)
  and [metadata rejection tests](../../../internal/controller/helpers_test.go).
- [Endpoint and operator transport policy](../../../internal/keycloak/transport.go)
  and [syntax, credential, CA and enterprise tests](../../../internal/keycloak/transport_test.go).
- [Chart transport validation](https://github.com/Alien6-Studio/hankoshell-operator/blob/fb9c6e60037a69bb6bde719c73a1b6592606466b/tests/chart/keycloak-transport.py).
- [Transport and network deployment contract](../../secure-deployment.md).
