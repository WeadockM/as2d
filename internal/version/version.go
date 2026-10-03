// Package version reports which version of as2d is running.
package version

import "runtime/debug"

// Version is set at build time for release builds:
//
//	go build -ldflags "-X github.com/WeadockM/as2d/internal/version.Version=v0.2.0" ./cmd/...
var Version = ""

// String returns the version: the one set at build time, else the module
// version recorded by "go install ...@vX.Y.Z", else "dev" plus the commit
// for builds from a git checkout.
func String() string {
	if Version != "" {
		return Version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	rev, dirty := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	switch {
	case rev == "":
		return "dev"
	case dirty:
		return "dev-" + rev + "-modified"
	default:
		return "dev-" + rev
	}
}
