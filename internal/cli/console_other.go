//go:build !windows

package cli

// StartedByDoubleClick is always false outside Windows.
func StartedByDoubleClick() bool { return false }
