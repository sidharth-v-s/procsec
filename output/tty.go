//go:build linux

package output

import (
	"os"
	"unsafe"

	"syscall"
)

// tcgets is the Linux ioctl request number for TCGETS (fetch termios).
// Defined by hand rather than imported from golang.org/x/sys/unix so
// this project stays dependency-free (single static binary, stdlib
// only — see design doc's language-choice rationale).
const tcgets = 0x5401

// termios mirrors the kernel's struct termios layout closely enough
// for TCGETS to succeed/fail correctly; we never read its fields, we
// only care whether the ioctl itself succeeds (which it only does on
// an actual terminal fd).
type termios struct {
	Iflag, Oflag, Cflag, Lflag uint32
	Line                       byte
	Cc                         [32]byte
	Ispeed, Ospeed             uint32
}

// IsTerminal reports whether f is connected to a terminal. Used to
// auto-disable color when stdout is piped/redirected (e.g.
// `procsec ps | grep foo`) even if the user didn't pass --no-color —
// matching how ls, grep, and most other color-capable CLI tools behave.
func IsTerminal(f *os.File) bool {
	var t termios
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(tcgets),
		uintptr(unsafe.Pointer(&t)),
	)
	return errno == 0
}
