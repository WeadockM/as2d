// Package cli holds behaviour shared by the command-line programs, mainly
// to make them friendly when started by double-clicking on Windows.
package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// DefaultConfigPath is the configuration file used when -config is not
// given: /etc/as2d/config.json, or on Windows, config.json next to the
// program.
func DefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		if exe, err := os.Executable(); err == nil {
			return filepath.Join(filepath.Dir(exe), "config.json")
		}
		return "config.json"
	}
	return "/etc/as2d/config.json"
}

// Hold keeps a console window that was opened by double-clicking the
// program on screen until Enter is pressed, so its output can be read.
// From a terminal or a service it does nothing.
func Hold() {
	if !StartedByDoubleClick() {
		return
	}
	fmt.Fprint(os.Stderr, "\nPress Enter to close this window.")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// Explain tells someone who double-clicked the program how to run it. note,
// if not empty, is added as a final paragraph. It does nothing when started
// from a terminal.
func Explain(program, usage, note string) {
	if !StartedByDoubleClick() {
		return
	}
	fmt.Fprintf(os.Stderr, `
%[1]s is a command-line program. Run it from a terminal (PowerShell) in this
folder, for example:

    .\%[1]s.exe %[2]s
`, program, usage)
	if note != "" {
		fmt.Fprintf(os.Stderr, "\n%s\n", note)
	}
	fmt.Fprintln(os.Stderr, "\nGetting started: https://github.com/WeadockM/as2d#local-testing")
}
