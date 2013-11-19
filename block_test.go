package xxtea

import "testing"

func uint32ArrayEq(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}

	for i, _ := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

type blockTestVector struct {
	key        []uint32
	plaintext  []uint32
	ciphertext []uint32
}

var blockTestVectors = []blockTestVector{
	{
		[]uint32{0x633985cf, 0x5e1fe2a0, 0x4a059113, 0xc8894f09},
		[]uint32{0xe31fa38a, 0x30d48e0b},
		[]uint32{0x21917c1, 0xe172a0c6},
	},
	{
		[]uint32{0xbdd52e8a, 0x838b9c44, 0xc7ec47e2, 0x671b838a},
		[]uint32{0x9e547ee3, 0xc9891271},
		[]uint32{0x3a4354c, 0x55341ca0},
	},
	{
		[]uint32{0x67dff6e0, 0x5c3be544, 0x72772159, 0x6cd17f95},
		[]uint32{0x12ce3d62, 0x91d4eab8},
		[]uint32{0x6b495cb0, 0xbfed2c7},
	},
	{
		[]uint32{0xc1fe3a49, 0xfd140ada, 0x96434146, 0xa99ac338},
		[]uint32{0xd23efe32, 0xb81e0bff},
		[]uint32{0x41a5575a, 0x162d8cdb},
	},
	{
		[]uint32{0xd84a9f7a, 0x2c8000a7, 0xfed1c823, 0x6e2da981},
		[]uint32{0x14bd15df, 0x499a9926},
		[]uint32{0x58761493, 0x1cc3d858},
	},
	{
		[]uint32{0x6ac98d76, 0x9d8412b, 0xe9ea1c08, 0xe3ed1810},
		[]uint32{0xcc163a84, 0x17a0b835},
		[]uint32{0xc025a875, 0x322218d5},
	},
	{
		[]uint32{0x70c1d0a7, 0x216709fc, 0x903c1298, 0xfd26f6c4},
		[]uint32{0x3157b682, 0xab26e7f3},
		[]uint32{0xf2e08e05, 0xc6a9f8dc},
	},
	{
		[]uint32{0x4702d3d1, 0xb3938826, 0x8eb71850, 0x7db0da44},
		[]uint32{0x13ab9fb, 0x4c79ab39},
		[]uint32{0x1f497601, 0xc5b3d8ee},
	},
}

func TestBlockEncryption(t *testing.T) {
	for n, v := range blockTestVectors {
		t.Logf("==========: test vector %d", n)
		t.Logf("       key: %+v", v.key)
		t.Logf(" plaintext: %+v", v.plaintext)
		t.Logf("ciphertext: %+v", v.ciphertext)

		buf := make([]uint32, len(v.plaintext))
		encode(buf, v.plaintext, v.key)

		t.Logf("  encode(): %+v", buf)

		if !uint32ArrayEq(v.ciphertext, buf) {
			t.Fatalf("      FAIL: encoded data did not match expected ciphertext")
		} else {
			t.Logf("          : test vector %d passed", n)
		}
	}
}
