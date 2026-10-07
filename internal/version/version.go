// Package version carries the build-time identity of this operator binary.
package version

// Agent is the operator build identifier reported to the Hub with every
// heartbeat. Release images stamp it with the immutable image tag (git short
// revision) via -ldflags; "dev" identifies local, unreleased builds.
var Agent = "dev"
