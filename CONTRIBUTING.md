# Contributing

Use English for issues, pull requests, documentation, and commit messages.
Participation follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Keep a pull request focused and describe the problem, resulting behavior,
validation, and operational impact. Add a sign-off with `git commit -s`.

Run `make check arch lint generated-check vuln` with the pinned tools.
`make lint` installs and verifies golangci-lint in the ignored `.tools` directory.
Behavior changes need meaningful regression tests. Changes to CRDs, provider
ownership, deletion, adoption, or authentication need migration and rollback
instructions. Use synthetic fixtures and keep credentials and tenant data out
of the repository.

Contributions are licensed under Apache-2.0. Maintainers review changes before
merge. Report security issues using [SECURITY.md](SECURITY.md).
