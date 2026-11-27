package keccak

import (
	"maps"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"testing"
)

func randomMsgs(r *rand.Rand, n, maxLen int) [][]byte {
	msgs := make([][]byte, n)
	for i := range msgs {
		msgs[i] = make([]byte, r.IntN(maxLen+1))
		for j := range msgs[i] {
			msgs[i][j] = byte(r.Uint32())
		}
	}
	return msgs
}

func checkSumMany(t *testing.T, msgs [][]byte) {
	t.Helper()
	out := make([][32]byte, len(msgs))
	SumMany256(msgs, out)
	for i, msg := range msgs {
		if want := Sum256(msg); out[i] != want {
			t.Fatalf("msg %d of %d (len %d): got %x, want %x", i, len(msgs), len(msg), out[i], want)
		}
	}
}

// forEachX4 runs f once per four-lane kernel this CPU can run, and once without any.
func forEachX4(t *testing.T, f func(t *testing.T)) {
	kernels := map[string]x4Kernel{"scalar": x4None}
	maps.Copy(kernels, availableX4())
	for name, k := range kernels {
		t.Run(name, func(t *testing.T) {
			old := x4
			x4 = k
			t.Cleanup(func() { x4 = old })
			f(t)
		})
	}
}

// TestX4Kernels logs the kernel SumMany256 selected. With KECCAK_REQUIRE_X4 set it fails unless
// that kernel is the selected one, so a CI job can prove which kernel it ran.
func TestX4Kernels(t *testing.T) {
	t.Logf("selected: %v, available: %v", x4, slices.Sorted(maps.Keys(availableX4())))
	if want := os.Getenv("KECCAK_REQUIRE_X4"); want != "" && x4.String() != want {
		t.Fatalf("KECCAK_REQUIRE_X4=%s, but SumMany256 selected %v", want, x4)
	}
}

func TestSumMany256(t *testing.T) {
	forEachX4(t, func(t *testing.T) {
		r := rand.New(rand.NewPCG(1, 2))
		for n := range 21 {
			t.Run(strconv.Itoa(n), func(t *testing.T) {
				for range 20 {
					checkSumMany(t, randomMsgs(r, n, 4*rate))
				}
			})
		}
		edges := [][]byte{
			nil,
			{},
			make([]byte, rate-1), make([]byte, rate), make([]byte, rate+1),
			make([]byte, 2*rate), make([]byte, 100*rate+3), make([]byte, 1),
		}
		checkSumMany(t, edges)
		checkSumMany(t, append(edges, edges...))
	})
}

// A message much longer than the rest keeps one lane busy while the others take new messages.
func TestSumMany256MixedLengths(t *testing.T) {
	forEachX4(t, func(t *testing.T) {
		r := rand.New(rand.NewPCG(3, 4))
		msgs := randomMsgs(r, 50, 2*rate)
		msgs[7] = make([]byte, 300*rate+11)
		msgs[30] = make([]byte, 40*rate)
		checkSumMany(t, msgs)
	})
}

func TestX4SelfTestDetectsWrongHash(t *testing.T) {
	wrong := func(msgs [][]byte, out [][32]byte) {
		for i, msg := range msgs {
			out[i] = Sum256(msg)
		}
		out[len(out)-1][0] ^= 1
	}
	if matchesSum256(wrong) {
		t.Fatal("self-test accepted a wrong hash")
	}
}

// FuzzSumMany256 runs SumMany256 and every four-lane kernel, whatever the batch size.
func FuzzSumMany256(f *testing.F) {
	f.Add([]byte("seed"), uint16(5))
	f.Fuzz(func(t *testing.T, data []byte, split uint16) {
		var msgs [][]byte
		step := int(split%300) + 1
		for len(data) > 0 {
			n := min(step, len(data))
			msgs = append(msgs, data[:n])
			data = data[n:]
			step = step*7%301 + 1
		}
		checkSumMany(t, msgs)
		out := make([][32]byte, len(msgs))
		for name, k := range availableX4() {
			sumManyX4(k, msgs, out)
			for i, msg := range msgs {
				if want := Sum256(msg); out[i] != want {
					t.Fatalf("%s: msg %d of %d (len %d): got %x, want %x", name, i, len(msgs), len(msg), out[i], want)
				}
			}
		}
	})
}

// BenchmarkSumMany256 compares a Sum256 loop with each four-lane kernel, per message shape and
// batch size. ns/op is per batch; MB/s counts message bytes.
func BenchmarkSumMany256(b *testing.B) {
	shapes := []struct {
		name   string
		minLen int
		maxLen int
	}{
		{"key32", 32, 32},
		{"key64", 64, 64},
		{"node100-600", 100, 600},
		{"tx0-544", 0, 4 * rate},
	}
	kernels := availableX4()
	names := slices.Sorted(maps.Keys(kernels))
	for _, shape := range shapes {
		for _, n := range []int{4, 16, 64, 256, 1024} {
			r := rand.New(rand.NewPCG(5, uint64(n)))
			msgs := make([][]byte, n)
			bytes := 0
			for i := range msgs {
				msgs[i] = make([]byte, shape.minLen+r.IntN(shape.maxLen-shape.minLen+1))
				for j := range msgs[i] {
					msgs[i][j] = byte(r.Uint32())
				}
				bytes += len(msgs[i])
			}
			out := make([][32]byte, n)
			prefix := shape.name + "/n=" + strconv.Itoa(n) + "/"
			b.Run(prefix+"Sum256", func(b *testing.B) {
				b.SetBytes(int64(bytes))
				b.ReportAllocs()
				for b.Loop() {
					for i, m := range msgs {
						out[i] = Sum256(m)
					}
				}
			})
			for _, name := range names {
				b.Run(prefix+name, func(b *testing.B) {
					b.SetBytes(int64(bytes))
					b.ReportAllocs()
					for b.Loop() {
						sumManyX4(kernels[name], msgs, out)
					}
				})
			}
		}
	}
}
