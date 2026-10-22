//go:build amd64 && !purego

package keccak

import (
	"math/rand"
	"testing"
)

func TestAVX512MatchesBMI2(t *testing.T) {
	if !useAVX512 || !useASM {
		t.Skip("AVX-512VL or BMI2 unavailable on this CPU")
	}
	rng := rand.New(rand.NewSource(1))
	for i := range 10000 {
		var a, b [200]byte
		var buf [rate]byte
		rng.Read(a[:])
		rng.Read(buf[:])
		b = a
		p := &buf[0]
		if i%2 == 0 {
			p = nil
		}
		keccakF1600AVX512(&a, p)
		keccakF1600BMI2(&b, p)
		if a != b {
			t.Fatalf("iteration %d (buf %v): AVX-512 diverges from BMI2\ngot:  %x\nwant: %x", i, p != nil, a, b)
		}
	}
}

var kernels = []struct {
	name string
	f    func(*[200]byte, *byte)
}{
	{"bmi2", keccakF1600BMI2},
	{"avx512", keccakF1600AVX512},
}

func BenchmarkKeccakF1600(b *testing.B) {
	for _, k := range kernels {
		b.Run(k.name, func(b *testing.B) {
			var s [200]byte
			for b.Loop() {
				k.f(&s, nil)
			}
		})
	}
}

func BenchmarkSum256Kernel(b *testing.B) {
	defer func(v bool) { useAVX512 = v }(useAVX512)
	for _, size := range []int{32, 64, 136, 4096} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i)
		}
		for _, avx := range []bool{false, true} {
			name := "bmi2"
			if avx {
				name = "avx512"
			}
			b.Run(benchName(size)+"/"+name, func(b *testing.B) {
				useAVX512 = avx
				b.SetBytes(int64(size))
				for b.Loop() {
					Sum256(data)
				}
			})
		}
	}
}
