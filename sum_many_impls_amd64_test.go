//go:build amd64 && !purego

package keccak

import (
	"testing"

	"golang.org/x/sys/cpu"
)

func availableX4() map[string]x4Kernel {
	kernels := map[string]x4Kernel{}
	if hasX4AVX2() {
		kernels["avx2"] = x4AVX2
	}
	if hasX4AVX512() {
		kernels["avx512"] = x4AVX512
	}
	return kernels
}

// The AVX-512 kernel shares the AVX2 absorb, so a CPU (or VM) that reports AVX-512 without AVX2
// must not get it.
func TestX4AVX512NeedsAVX2(t *testing.T) {
	saved := cpu.X86
	t.Cleanup(func() { cpu.X86 = saved })
	cpu.X86.HasAVX512F, cpu.X86.HasAVX512VL, cpu.X86.HasAVX2 = true, true, false
	if hasX4AVX512() {
		t.Fatal("AVX-512 kernel selectable without AVX2")
	}
}
