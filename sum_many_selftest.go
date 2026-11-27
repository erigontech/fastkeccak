package keccak

// matchesSum256 reports whether sumMany hashes messages of every block-count pattern a lane
// can see, including lanes that finish at different times, the same as Sum256.
func matchesSum256(sumMany func(msgs [][]byte, out [][32]byte)) bool {
	sizes := []int{0, 1, rate - 1, rate, rate + 1, 3*rate + 7, 2 * rate, 55, 700}
	msgs := make([][]byte, len(sizes))
	for i, n := range sizes {
		msgs[i] = make([]byte, n)
		for j := range msgs[i] {
			msgs[i][j] = byte(j*31 + i)
		}
	}
	out := make([][32]byte, len(msgs))
	sumMany(msgs, out)
	for i, msg := range msgs {
		if out[i] != Sum256(msg) {
			return false
		}
	}
	return true
}
