// rizin - LGPL - Copyright 2017 - pancake

package rzpipe

import (
	"errors"
	"runtime"
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

// goString converts a C string (null-terminated) to a Go string
func goString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var length int
	for {
		b := *(*byte)(unsafe.Pointer(ptr + uintptr(length)))
		if b == 0 {
			break
		}
		length++
	}
	if length == 0 {
		return ""
	}
	bytes := make([]byte, length)
	for i := 0; i < length; i++ {
		bytes[i] = *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
	}
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

func NativeLoad() error {
	if libLoaded {
		return nil
	}

	rzCoreName, libcName := getLibraryNames()

	librz, err := purego.Dlopen(rzCoreName, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return err
	}

	purego.RegisterLibFunc(&rz_core_new, librz, "rz_core_new")
	if rz_core_new == nil {
		return errors.New("failed to load rz_core_new")
	}

	purego.RegisterLibFunc(&rz_core_free, librz, "rz_core_free")
	if rz_core_free == nil {
		return errors.New("failed to load rz_core_free")
	}

	purego.RegisterLibFunc(&rz_core_cmd_str, librz, "rz_core_cmd_str")
	if rz_core_cmd_str == nil {
		return errors.New("failed to load rz_core_cmd_str")
	}

	// Load free function from libc
	libc, err := purego.Dlopen(libcName, purego.RTLD_NOW)
	if err != nil {
		return err
	}

	purego.RegisterLibFunc(&libc_free, libc, "free")
	if libc_free == nil {
		return errors.New("failed to load free from libc")
	}

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
	rz_core_free(rzp.core)
	rzp.core = 0
	return nil
}

func NewNativePipe(file string) (*Pipe, error) {
	if err := NativeLoad(); err != nil {
		return nil, err
	}
	rz := rz_core_new()
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
		rzp.NativeCmd("o " + file)
	}
	return rzp, nil
}
