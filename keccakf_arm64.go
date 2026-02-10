//go:build arm64 && !purego

package keccak

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

// Apple Silicon always has Armv8.2-A SHA3 extensions (VEOR3, VRAX1, VXAR, VBCAX).
// On other ARM64 platforms, detect at runtime via CPU feature flags.
var useSHA3 = runtime.GOOS == "darwin" || runtime.GOOS == "ios" || cpu.ARM64.HasSHA3

//go:noescape
func keccakF1600NEON(a *[200]byte)

func keccakF1600(a *[200]byte) {
	if useSHA3 {
		keccakF1600NEON(a)
	} else {
		keccakF1600Generic(a)
	}
}
