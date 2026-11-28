//go:build !amd64 || purego

package keccak

func permuteX4(x4Kernel, *[100]uint64, *[4]*byte) { panic("keccak: no four-lane kernel") }
