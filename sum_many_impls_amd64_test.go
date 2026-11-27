//go:build amd64 && !purego

package keccak

import "golang.org/x/sys/cpu"

func availableX4() map[string]x4Kernel {
	kernels := map[string]x4Kernel{}
	if cpu.X86.HasAVX2 {
		kernels["avx2"] = x4AVX2
	}
	if cpu.X86.HasAVX512F && cpu.X86.HasAVX512VL {
		kernels["avx512"] = x4AVX512
	}
	return kernels
}
