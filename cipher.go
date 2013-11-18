package xxtea

import (
	"crypto/cipher"
	"strconv"
)

type KeySizeError int

func (k KeySizeError) Error() string {
	return "xxtea: invalid key size: " + strconv.Itoa(int(k))
}

type BlockSizeError int

func (b BlockSizeError) Error() string {
	return "xxtea: invalid block size: " + strconv.Itoa(int(b))
}

// Internal state for the XXTEA block cipher.
type _XXTEA struct {
	blockSize int
	key       [4]uint32
}

func (x *_XXTEA) BlockSize() int {
	return x.blockSize
}

func (x *_XXTEA) Encrypt(dst, src []byte) {
	// XXX: There is no block size checking here.

	// Convert bytes to uint32s.
	srcInts := bytesToUint32s(src)

	// Create destination buffer.
	dstInts := make([]uint32, len(dst)/4)

	// Encrypt.
	encode(dstInts, srcInts, x.key[:])

	// Convert back to bytes.
	byteResult := uint32sToBytes(dstInts)

	// Copy to result.
	copy(dst, byteResult)
}

func (x *_XXTEA) Decrypt(dst, src []byte) {
	// XXX: There is no block size checking here.

	// Convert bytes to uint32s.
	srcInts := bytesToUint32s(src)

	// Create destination buffer.
	dstInts := make([]uint32, len(dst)/4)

	// Decrypt.
	decode(dstInts, srcInts, x.key[:])

	// Convert back to bytes.
	byteResult := uint32sToBytes(dstInts)

	// Copy to result.
	copy(dst, byteResult)
}

// New creates and returns a new cipher.Block.
// Argument key should be 128 bits (16 bytes).
// Argument blockSize should be a block size in bytes. XXTEA supports
// arbitrarily-sized blocks that are at least 8 bytes long, with a length
// that is a multiple of 4 bytes.
func New(key []byte, blockSize int) (cipher.Block, error) {
	// XXTEA uses a 128 bit (16 byte) key size.
	if len(key) != 16 {
		return nil, KeySizeError(len(key))
	}

	// XXTEA supports arbitrary block sizes that are 64 bits or larger, and multiples of 32 bits.
	if blockSize < 8 || (blockSize%4) != 0 {
		return nil, BlockSizeError(blockSize)
	}

	var k = make([]uint32, 4)
	k = bytesToUint32s(key)

	var k2 [4]uint32
	copy(k2[:], k)

	x := &_XXTEA{
		key:       k2,
		blockSize: blockSize,
	}

	return x, nil
}
