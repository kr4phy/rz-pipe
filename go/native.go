// rizin - LGPL - Copyright 2017 - pancake

package rzpipe

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"github.com/ebitengine/purego"
)

var (
	libLoaded       bool = false
	rz_core_new     func() uintptr
	rz_core_free    func(uintptr)
	rz_core_cmd_str func(uintptr, string) uintptr
	libc_free       func(uintptr)
)

// goString converts a C string (null-terminated) to a Go string.
// The caller must ensure the pointer is valid and points to a null-terminated string.
// A maximum length limit is applied to prevent reading beyond allocated memory.
func goString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	const maxLen = 1 << 20 // 1MB safety limit
	var length int
	for length < maxLen {
		b := *(*byte)(unsafe.Pointer(ptr + uintptr(length)))
		if b == 0 {
			break
		}
		length++
	}
	if length == 0 {
		return ""
	}
	bytes := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), length)
	return string(bytes)
}

// getLibraryNames returns platform-specific library names for rizin core and libc
func getLibraryNames() (rzCoreName string, libcName string) {
	switch runtime.GOOS {
	case "darwin":
		return "librz_core.dylib", "libSystem.B.dylib"
	case "windows":
		return "rz_core.dll", "msvcrt.dll"
	default: // linux and others
		return "librz_core.so", "libc.so.6"
	}
}

func NativeLoad() (err error) {
	if libLoaded {
		return nil
	}

	rzCoreName, libcName := getLibraryNames()

	librz, err := purego.Dlopen(rzCoreName, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return err
	}

	// Load free function from libc first (needed for cleanup)
	libc, err := purego.Dlopen(libcName, purego.RTLD_NOW)
	if err != nil {
		return err
	}

	// RegisterLibFunc panics if symbol not found, so we use recover
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to load symbol: %v", r)
		}
	}()

	purego.RegisterLibFunc(&rz_core_new, librz, "rz_core_new")
	purego.RegisterLibFunc(&rz_core_free, librz, "rz_core_free")
	purego.RegisterLibFunc(&rz_core_cmd_str, librz, "rz_core_cmd_str")
	purego.RegisterLibFunc(&libc_free, libc, "free")

	libLoaded = true
	return nil
}

func (rzp *Pipe) NativeCmd(cmd string) (string, error) {
	ptr := rz_core_cmd_str(rzp.core, cmd)
	if ptr == 0 {
		return "", errors.New("command failed")
	}

	// Convert C string to Go string
	result := goString(ptr)

	// Free memory allocated by rz_core_cmd_str (important!)
	libc_free(ptr)

	return result, nil
}

func (rzp *Pipe) NativeClose() error {
	if rzp.core == 0 {
		return nil // Already closed
	}
	rz_core_free(rzp.core)
	rzp.core = 0
	return nil
}

// quoteFilePath escapes special characters in file paths for rizin commands
func quoteFilePath(file string) string {
	// Escape special characters that could be interpreted as command separators
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"\"", "\\\"",
		";", "\\;",
		"`", "\\`",
		"$", "\\$",
		"\n", "",
		"\r", "",
	)
	return "\"" + replacer.Replace(file) + "\""
}

func NewNativePipe(file string) (*Pipe, error) {
	if err := NativeLoad(); err != nil {
		return nil, err
	}
	rz := rz_core_new()
	if rz == 0 {
		return nil, errors.New("failed to create rizin core")
	}
	rzp := &Pipe{
		File: file,
		core: rz,
		cmd: func(rzp *Pipe, cmd string) (string, error) {
			return rzp.NativeCmd(cmd)
		},
		close: func(rzp *Pipe) error {
			return rzp.NativeClose()
		},
	}
	if file != "" {
		_, err := rzp.NativeCmd("o " + quoteFilePath(file))
		if err != nil {
			rzp.NativeClose()
			return nil, err
		}
	}
	return rzp, nil
}
