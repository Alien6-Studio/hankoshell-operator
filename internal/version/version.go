// Package version carries the build-time identity of this operator binary.
package version

// Agent is the operator build identifier reported to the Hub with every
// heartbeat. Builds stamp the reviewed technical SemVer via -ldflags.
// The default identifies current unreleased development.
var Agent = "0.1.0-dev.0"
