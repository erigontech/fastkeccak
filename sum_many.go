package keccak

//go:generate go run gen_keccakx4.go
//go:generate go run github.com/klauspost/asmfmt/cmd/asmfmt@v1.3.2 -w keccakx4_amd64.s

import (
	"encoding/binary"
	"unsafe"
)

// SumMany256 sets out[i] to the Keccak-256 hash of msgs[i]; out must be at least as long as
// msgs, and must not overlap any message. On amd64 with AVX2 or AVX-512 it hashes four
// messages at a time, which is faster than calling Sum256 in a loop when there are several
// messages; elsewhere it is that loop.
func SumMany256(msgs [][]byte, out [][32]byte) {
	if len(out) < len(msgs) {
		panic("keccak: SumMany256 out is shorter than msgs")
	}
	if x4 == x4None || len(msgs) < minX4Msgs {
		for i, msg := range msgs {
			out[i] = Sum256(msg)
		}
		return
	}
	sumManyX4(x4, msgs, out)
}

// minX4Msgs is the smallest batch the four-lane kernels take: a four-lane permutation costs
// about 2.3 scalar ones, so with two messages the Sum256 loop is faster, with three it is not.
const minX4Msgs = 3

// x4Kernel selects a four-lane permutation; see permuteX4.
type x4Kernel uint8

const (
	x4None x4Kernel = iota
	x4AVX2
	x4AVX512
)

func (k x4Kernel) String() string {
	switch k {
	case x4AVX2:
		return "avx2"
	case x4AVX512:
		return "avx512"
	default:
		return "none"
	}
}

// x4 is the kernel SumMany256 uses, x4None when the CPU has no four-lane kernel.
var x4 x4Kernel

var zeroBlock [rate]byte

// sumManyX4 runs four messages at once; a lane that finishes takes the next message, so
// messages of different lengths do not leave lanes idle.
func sumManyX4(k x4Kernel, msgs [][]byte, out [][32]byte) {
	var (
		abuf   [100 + 3]uint64
		blocks [4]*byte
		pad    [4 * rate]byte
		cur    [4]int
		pos    [4]int
	)
	a := align32(&abuf)
	order := longestFour(msgs)
	active := 0
	for lane := range 4 {
		if cur[lane] = order.first[lane]; cur[lane] >= 0 {
			active++
		}
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
			if cur[lane] = order.take(len(msgs)); cur[lane] >= 0 {
				active++
			}
		}
	}
}

// align32 returns the 32-byte aligned state inside buf, so that the kernels' 32-byte loads and
// stores do not cross cache lines.
func align32(buf *[100 + 3]uint64) *[100]uint64 {
	off := (-uintptr(unsafe.Pointer(buf)) & 31) / 8
	return (*[100]uint64)(buf[off : off+100])
}

// msgOrder hands out the messages: the four longest first, one per lane, so that a long
// message does not end up running alone at the end; then the others in index order.
type msgOrder struct {
	first [4]int // longest first; -1 when there are fewer messages
	next  int
}

func longestFour(msgs [][]byte) msgOrder {
	o := msgOrder{first: [4]int{-1, -1, -1, -1}}
	for i, m := range msgs {
		j := len(o.first) - 1
		if o.first[j] >= 0 && len(m) <= len(msgs[o.first[j]]) {
			continue
		}
		for ; j > 0 && (o.first[j-1] < 0 || len(m) > len(msgs[o.first[j-1]])); j-- {
			o.first[j] = o.first[j-1]
		}
		o.first[j] = i
	}
	return o
}

// take returns the next message after the first four, or -1 when there is none.
func (o *msgOrder) take(n int) int {
	for ; o.next < n; o.next++ {
		if i := o.next; i != o.first[0] && i != o.first[1] && i != o.first[2] && i != o.first[3] {
			o.next++
			return i
		}
	}
	return -1
}
