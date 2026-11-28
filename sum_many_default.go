//go:build !amd64 || purego

package keccak

func permuteX4(x4Kernel, *[100]uint64, *[4]*byte) { panic("keccak: no four-lane kernel") }

func finishLane(*[100]uint64, int, []byte) [32]byte { panic("keccak: no four-lane kernel") }
