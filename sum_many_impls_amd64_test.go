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

// Every kernel needs all of its CPU features: the AVX-512 kernel shares the AVX2 absorb, and a
// lane left alone at the end is finished with the BMI2 scalar kernel. Each case starts from all
// features present and removes one.
func TestX4RequiredFeatures(t *testing.T) {
	saved := cpu.X86
	t.Cleanup(func() { cpu.X86 = saved })
	for _, tc := range []struct {
		missing      string
		flag         *bool
		avx2, avx512 bool
	}{
		{"none", nil, true, true},
		{"AVX2", &cpu.X86.HasAVX2, false, false},
		{"BMI1", &cpu.X86.HasBMI1, false, false},
		{"BMI2", &cpu.X86.HasBMI2, false, false},
		{"AVX512F", &cpu.X86.HasAVX512F, true, false},
		{"AVX512VL", &cpu.X86.HasAVX512VL, true, false},
	} {
		cpu.X86.HasAVX2, cpu.X86.HasBMI1, cpu.X86.HasBMI2 = true, true, true
		cpu.X86.HasAVX512F, cpu.X86.HasAVX512VL = true, true
		if tc.flag != nil {
			*tc.flag = false
		}
		if got := hasX4AVX2(); got != tc.avx2 {
			t.Errorf("without %s: AVX2 kernel selectable = %v, want %v", tc.missing, got, tc.avx2)
		}
		if got := hasX4AVX512(); got != tc.avx512 {
			t.Errorf("without %s: AVX-512 kernel selectable = %v, want %v", tc.missing, got, tc.avx512)
		}
	}
}
