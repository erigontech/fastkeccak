//go:build !arm64 || purego

package keccak

import (
	"hash"

	"golang.org/x/crypto/sha3"
)

// Sum256 computes the Keccak-256 hash of data.
// On non-arm64 platforms, delegates to x/crypto/sha3.NewLegacyKeccak256().
func Sum256(data []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// Hasher is a streaming Keccak-256 hasher wrapping x/crypto/sha3.
type Hasher struct {
	h hash.Hash
}

func (h *Hasher) init() {
	if h.h == nil {
		h.h = sha3.NewLegacyKeccak256()
	}
}

// Reset resets the hasher to its initial state.
func (h *Hasher) Reset() {
	h.init()
	h.h.Reset()
}

// Write absorbs data into the hasher.
func (h *Hasher) Write(p []byte) {
	h.init()
	h.h.Write(p)
}

// Sum256 finalizes and returns the 32-byte Keccak-256 digest.
// Does not modify the hasher state.
func (h *Hasher) Sum256() [32]byte {
	h.init()
	var out [32]byte
	h.h.Sum(out[:0])
	return out
}
