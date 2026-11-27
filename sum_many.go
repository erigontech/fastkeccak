package keccak

//go:generate go run gen_keccakx4.go
//go:generate go run github.com/klauspost/asmfmt/cmd/asmfmt@v1.3.2 -w keccakx4_amd64.s

import (
	"encoding/binary"
	"slices"
	"sync"
	"unsafe"
)

// SumMany256 sets out[i] to the Keccak-256 hash of msgs[i]; out must be at least as long as
// msgs, and must not overlap any message. On amd64 with AVX2 or AVX-512 it hashes four
// messages at a time, which is faster than calling Sum256 in a loop when there are several
// messages; elsewhere it is that loop.
func SumMany256(msgs [][]byte, out [][32]byte) {
	_ = out[:len(msgs)]
	if x4 == x4None || len(msgs) < 4 {
		for i, msg := range msgs {
			out[i] = Sum256(msg)
		}
		return
	}
	sumManyX4(x4, msgs, out)
}

// x4Kernel selects a four-lane permutation; see permuteX4.
type x4Kernel uint8

const (
	x4None x4Kernel = iota
	x4AVX2
	x4AVX512
)

// x4 is the kernel SumMany256 uses. It is x4None when no four-lane kernel is available or
// the startup self-test failed.
var x4 x4Kernel

var zeroBlock [rate]byte

// orderPool holds the message order of sumManyX4. It holds indexes only, so pooling it does
// not make the messages escape.
var orderPool = sync.Pool{New: func() any { return new([]int) }}

// sumManyX4 runs four messages at once; a lane that finishes takes the next message, so
// messages of different lengths do not leave lanes idle. The longest messages go first so
// the lanes run out together.
func sumManyX4(k x4Kernel, msgs [][]byte, out [][32]byte) {
	var (
		abuf   [100 + 3]uint64
		blocks [4]*byte
		pad    [4 * rate]byte
		cur    [4]int
		pos    [4]int
	)
	a := align32(&abuf)
	orderp := orderPool.Get().(*[]int)
	defer orderPool.Put(orderp)
	order := longestFirst(*orderp, msgs)
	*orderp = order
	next, active := 0, 0
	for lane := range 4 {
		cur[lane], next, active = takeNext(order, next, active)
	}
	for active > 0 {
		for lane := range 4 {
			if cur[lane] < 0 {
				blocks[lane] = &zeroBlock[0]
				continue
			}
			rest := msgs[cur[lane]][pos[lane]:]
			if len(rest) >= rate {
				blocks[lane] = &rest[0]
				continue
			}
			p := pad[lane*rate : (lane+1)*rate]
			clear(p)
			n := copy(p, rest)
			p[n] ^= 0x01
			p[rate-1] ^= 0x80
			blocks[lane] = &p[0]
		}
		permuteX4(k, a, &blocks)
		for lane := range 4 {
			if cur[lane] < 0 {
				continue
			}
			if len(msgs[cur[lane]])-pos[lane] >= rate {
				pos[lane] += rate
				continue
			}
			o := &out[cur[lane]]
			for w := range 4 {
				binary.LittleEndian.PutUint64(o[8*w:], a[4*w+lane])
			}
			for w := range 25 {
				a[4*w+lane] = 0
			}
			active--
			pos[lane] = 0
			cur[lane], next, active = takeNext(order, next, active)
		}
	}
}

// align32 returns the 32-byte aligned state inside buf, so that the kernels' 32-byte loads and
// stores do not cross cache lines.
func align32(buf *[100 + 3]uint64) *[100]uint64 {
	off := (-uintptr(unsafe.Pointer(buf)) & 31) / 8
	return (*[100]uint64)(buf[off : off+100])
}

// takeNext returns the next message for a lane, or -1 when there is none.
func takeNext(order []int, next, active int) (msg, newNext, newActive int) {
	if next == len(order) {
		return -1, next, active
	}
	return order[next], next + 1, active + 1
}

func longestFirst(order []int, msgs [][]byte) []int {
	order = slices.Grow(order[:0], len(msgs))[:len(msgs)]
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(i, j int) int { return len(msgs[j]) - len(msgs[i]) })
	return order
}
