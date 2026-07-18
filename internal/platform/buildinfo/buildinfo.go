// Package buildinfo holds version and build metadata stamped at compile time via ldflags.
package buildinfo

import (
	"fmt"
	"runtime"
	"time"
)

// Build metadata injected via -ldflags at build time (see the
// justfile). The zero values identify an untagged local build.
var (
	// Version is the release version (git describe).
	Version = "dev"
	// GitCommit is the short commit hash the binary was built from.
	GitCommit = "unknown"
	// GitBranch is the branch the binary was built from.
	GitBranch = "unknown"
	// BuildTime is the UTC build timestamp (RFC 3339).
	BuildTime = "unknown"
)

var startTime = time.Now()

// BuildInfo returns the stamped build metadata plus the runtime's Go
// version, OS, and architecture, keyed by snake_case field name.
func BuildInfo() map[string]string {
	return map[string]string{
		"version":    Version,
		"git_commit": GitCommit,
		"git_branch": GitBranch,
		"build_time": BuildTime,
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
	}
}

// RuntimeInfo returns [BuildInfo] plus the process uptime.
func RuntimeInfo() map[string]string {
	info := BuildInfo()
	info["uptime"] = Uptime().String()
	return info
}

// Uptime returns how long the process has been running, truncated to
// whole seconds.
func Uptime() time.Duration {
	return time.Since(startTime).Truncate(time.Second)
}

// String returns a one-line human-readable build identification.
func String() string {
	return fmt.Sprintf("Spivot Server %s (%s@%s) built %s", Version, GitCommit, GitBranch, BuildTime)
}
