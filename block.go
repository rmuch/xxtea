package xxtea

// Endianness option.
// TODO: Expose this as a user option.
const endianness bool = false

// Convert a byte slice to a uint32 slice.
func bytesToUint32s(b []byte) []uint32 {
	size := len(b) / 4
	dst := make([]uint32, size)

	for i := 0; i < size; i++ {
		j := i * 4

		if endianness {
			dst[i] = uint32(b[j+0])<<24 | uint32(b[j+1])<<16 | uint32(b[j+2])<<8 | uint32(b[j+3])
		} else {
			dst[i] = uint32(b[j+0]) | uint32(b[j+1])<<8 | uint32(b[j+2])<<16 | uint32(b[j+3])<<24
		}
	}

	return dst
}

// Convert a uint32 slice to a byte slice.
func uint32sToBytes(w []uint32) []byte {
	size := len(w) * 4
	dst := make([]byte, size)

	for i := 0; i < len(w); i++ {
		j := i * 4

		if endianness {
			dst[j+0] = byte((w[i] >> 24) & 0xFF)
			dst[j+1] = byte((w[i] >> 16) & 0xFF)
			dst[j+2] = byte((w[i] >> 8) & 0xFF)
			dst[j+3] = byte((w[i]) & 0xFF)
		} else {
			dst[j+0] = byte((w[i]) & 0xFF)
			dst[j+1] = byte((w[i] >> 8) & 0xFF)
			dst[j+2] = byte((w[i] >> 16) & 0xFF)
			dst[j+3] = byte((w[i] >> 24) & 0xFF)
		}
	}

	return dst
}

// XXTEA constant DELTA.
const delta uint32 = 0x9e3779b9

// In the C reference implementation, this is a macro:
// #define MX (z>>5^y<<2) + (y>>3^z<<4)^(sum^y) + (k[p&3^e]^z);
func mx(y, z, sum, e uint32, k []uint32, p uint32) uint32 {
	return (((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[(p&3)^e] ^ z)))
}

// Code a block using the XXTEA cipher.
func encode(dst, src, key []uint32) {
	// Initialize cipher parameters.
	var n int32 = int32(len(src))
	var v []uint32 = dst
	var k []uint32 = key

	// Copy src to buffer for in-place encoding.
	copy(v, src)

	// Initialize locals.
	var y, z uint32 = 0, v[n-1]
	var sum, e uint32 = 0, 0
	var p, q uint32 = 0, uint32(6 + 52/n)

	for q > 0 {
		q--

		sum += delta
		e = (sum >> 2) & 3
		for p = 0; p < uint32(n-1); p++ {
			y = v[p+1]

			v[p] += mx(y, z, sum, e, k, p)
			z = v[p]
		}
		y = v[0]

		v[n-1] += mx(y, z, sum, e, k, p)
		z = v[n-1]
	}
}

// Decode a block using the XXTEA cipher.
func decode(dst, src, key []uint32) {
	// Initialize cipher parameters.
	var n int32 = int32(len(src))
	var v []uint32 = dst
	var k []uint32 = key

	// Copy src to buffer for in-place encoding.
	copy(v, src)

	// Initialize locals.
	var y, z uint32 = v[0], 0
	var sum, e uint32 = 0, 0
	var p, q uint32 = 0, uint32(6 + 52/n)

	sum = uint32(q) * delta
	for sum != 0 {
		e = (sum >> 2) & 3
		for p = uint32(n - 1); p > 0; p-- {
			z = v[p-1]

			v[p] -= mx(y, z, sum, e, k, p)
			y = v[p]
		}
		z = v[n-1]

		v[0] -= mx(y, z, sum, e, k, p)
		y = v[0]

		sum -= delta
	}
}
