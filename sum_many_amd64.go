//go:build amd64 && !purego

package keccak

import (
	"encoding/binary"

	"golang.org/x/sys/cpu"
)

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

// hasX4AVX2 needs BMI1 and BMI2 too: a lane left alone at the end is finished with the BMI2
// scalar kernel.
func hasX4AVX2() bool { return cpu.X86.HasAVX2 && cpu.X86.HasBMI1 && cpu.X86.HasBMI2 }

// hasX4AVX512 needs AVX2 too: the AVX-512 kernel shares the AVX2 absorb.
func hasX4AVX512() bool { return hasX4AVX2() && cpu.X86.HasAVX512F && cpu.X86.HasAVX512VL }

func init() {
	switch {
	case hasX4AVX512():
		x4 = x4AVX512
	case hasX4AVX2():
		x4 = x4AVX2
	}
}

// finishLane hashes the rest of a message from the state of one lane, with the scalar kernel.
func finishLane(a *[100]uint64, lane int, rest []byte) [32]byte {
	var state [200]byte
	for w := range 25 {
		binary.LittleEndian.PutUint64(state[8*w:], a[4*w+lane])
	}
	for len(rest) >= rate {
		xorAndPermute(&state, &rest[0])
		rest = rest[rate:]
	}
	xorIn(&state, rest)
	state[len(rest)] ^= 0x01
	state[rate-1] ^= 0x80
	keccakF1600(&state)
	return [32]byte(state[:32])
}
