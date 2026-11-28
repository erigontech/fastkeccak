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

// A lane left alone at the end is finished with the BMI2 scalar kernel, so the four-lane kernels
// need BMI1 and BMI2 too.
func TestX4NeedsBMI2(t *testing.T) {
	saved := cpu.X86
	t.Cleanup(func() { cpu.X86 = saved })
	cpu.X86.HasAVX2, cpu.X86.HasAVX512F, cpu.X86.HasAVX512VL = true, true, true
	cpu.X86.HasBMI1, cpu.X86.HasBMI2 = true, false
	if hasX4AVX2() || hasX4AVX512() {
		t.Fatal("four-lane kernel selectable without BMI2")
	}
}
