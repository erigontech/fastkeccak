//go:build !amd64 || purego

package keccak

func availableX4() map[string]x4Kernel { return nil }
