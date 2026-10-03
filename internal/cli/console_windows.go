package cli

import (
	"syscall"
	"unsafe"
)

var getConsoleProcessList = syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList")

// StartedByDoubleClick reports whether this process is the only one attached
// to its console. A program started from Explorer gets a new console of its
// own; one started from a terminal shares it with the shell, and a service
// has none.
func StartedByDoubleClick() bool {
	if getConsoleProcessList.Find() != nil {
		return false
	}
	var pids [2]uint32
	n, _, _ := getConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}
