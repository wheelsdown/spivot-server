// Package buildinfo holds version and build metadata stamped at compile time via ldflags.
package buildinfo

import (
	"fmt"
	"runtime"
	"time"
)

var (
	Version   = "dev"
	GitCommit = "unknown"
	GitBranch = "unknown"
	BuildTime = "unknown"
)

var startTime = time.Now()

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

func RuntimeInfo() map[string]string {
	info := BuildInfo()
	info["uptime"] = Uptime().String()
	return info
}

func Uptime() time.Duration {
	return time.Since(startTime).Truncate(time.Second)
}

func String() string {
	return fmt.Sprintf("Spivot Server %s (%s@%s) built %s", Version, GitCommit, GitBranch, BuildTime)
}
