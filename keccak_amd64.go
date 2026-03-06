//go:build amd64 && !purego

package keccak

import "golang.org/x/sys/cpu"

var useBMI2 = cpu.X86.HasBMI2

//go:noescape
func keccakF1600Generic(a *[200]byte)

//go:noescape
func keccakF1600BMI2(a *[200]byte)

//go:noescape
func xorAndPermuteGeneric(state *[200]byte, buf *byte)

//go:noescape
func xorAndPermuteBMI2(state *[200]byte, buf *byte)

func keccakF1600(a *[200]byte) {
	if useBMI2 {
		keccakF1600BMI2(a)
	} else {
		keccakF1600Generic(a)
	}
}

// Sum256 computes the Keccak-256 hash of data. Zero heap allocations.
func Sum256(data []byte) [32]byte { return sum256Sponge(data) }

// Hasher is a streaming Keccak-256 hasher. Designed for stack allocation.
type Hasher struct{ sponge }

func xorAndPermute(state *[200]byte, buf *byte) {
	if useBMI2 {
		xorAndPermuteBMI2(state, buf)
	} else {
		xorAndPermuteGeneric(state, buf)
	}
}
