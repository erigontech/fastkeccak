//go:build amd64 && !purego

package keccak

import "golang.org/x/sys/cpu"

// keccakX4AVX2 and keccakX4AVX512 absorb one rate block of each of four messages into a
// four-lane state and permute it. Lane i of message m is at a[4*i+m].
//
//go:noescape
func keccakX4AVX2(a *[100]uint64, blocks *[4]*byte)

//go:noescape
func keccakX4AVX512(a *[100]uint64, blocks *[4]*byte)

// permuteX4 calls the kernels directly rather than through a function value, so that the
// state and the message pointers in blocks can stay on the caller's stack.
func permuteX4(k x4Kernel, a *[100]uint64, blocks *[4]*byte) {
	switch k {
	case x4AVX2:
		keccakX4AVX2(a, blocks)
	case x4AVX512:
		keccakX4AVX512(a, blocks)
	default:
		panic("keccak: no four-lane kernel")
	}
}

func init() {
	switch {
	case cpu.X86.HasAVX512F && cpu.X86.HasAVX512VL:
		x4 = x4AVX512
	case cpu.X86.HasAVX2:
		x4 = x4AVX2
	}
	if x4 != x4None && !x4SelfTest(x4) {
		x4 = x4None
	}
}

// x4SelfTest reports whether kernel k gives the same hashes as Sum256.
func x4SelfTest(k x4Kernel) bool {
	return matchesSum256(func(msgs [][]byte, out [][32]byte) { sumManyX4(k, msgs, out) })
}
