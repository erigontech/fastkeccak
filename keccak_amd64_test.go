//go:build amd64 && !purego

package keccak

import "testing"

func BenchmarkKeccakF1600Generic(b *testing.B) {
	var state [200]byte
	b.ReportAllocs()
	for b.Loop() {
		keccakF1600Generic(&state)
	}
}

func BenchmarkKeccakF1600BMI2(b *testing.B) {
	var state [200]byte
	b.ReportAllocs()
	for b.Loop() {
		keccakF1600BMI2(&state)
	}
}
