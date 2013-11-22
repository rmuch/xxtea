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

var arbitrarySizeBlockTestVectors = []blockTestVector{
	{
		[]uint32{0x2b494cb0, 0x71b1d28b, 0x68dffe29, 0xbdad21e4},
		[]uint32{0x9994807b, 0x2c8acb51},
		[]uint32{0x2b0eecab, 0x79b6c257},
	},
	{
		[]uint32{0x53a75c70, 0xf00e4226, 0x7ddc619, 0xb97177ce},
		[]uint32{0xf84f514, 0x46b0e9c4, 0xc0d1dcc9},
		[]uint32{0x8ae286d6, 0x3e0dbaf9, 0x53a604c7},
	},
	{
		[]uint32{0x7fcc349b, 0x792462af, 0x1fec5f2d, 0x17f543ee},
		[]uint32{0x178f301d, 0xc778e521, 0xf3ae7d6, 0x3b7a95b5},
		[]uint32{0x7d4b1b0e, 0x55819c40, 0xe23da0b8, 0x77199b4d},
	},
	{
		[]uint32{0xd66d8cb9, 0x1e2a01f2, 0xe5e43558, 0xeffc0887},
		[]uint32{0x59afb57e, 0x77da693e, 0x28c94171, 0xb9816cf4, 0xbc792c76},
		[]uint32{0xe639180c, 0x3428c9b0, 0x3f23bf1, 0xe952bead, 0x156f00e3},
	},
	{
		[]uint32{0x60cddac6, 0xe0802e1, 0x375d8e7f, 0x562f5d0},
		[]uint32{0xc129df93, 0x2fbd55d4, 0x62d81c27, 0xd3c3c50e, 0xff38874f, 0xf246fbc9},
		[]uint32{0x23c14ee2, 0x2fe98548, 0x84501185, 0xde14bb3, 0x340315e5, 0x8570db7c},
	},
	{
		[]uint32{0xea73361d, 0xeecd4c8d, 0xfac7ecee, 0xef889da5},
		[]uint32{0xe7e40210, 0x3f3b2ecc, 0xa615c7a0, 0x4a6c617, 0x76fc50fe, 0xc10b8190, 0x184e609},
		[]uint32{0xb6770bd6, 0xbd5fb72c, 0x569781ff, 0x3441856d, 0xbc0b61a5, 0xff0bcca, 0xfcf3421d},
	},
	{
		[]uint32{0x1268cd20, 0x539ac661, 0xce2ab61, 0xd7dff6b9},
		[]uint32{0x1648c635, 0x90b24f9f, 0x6e9fa89a, 0x919b4e67, 0x1f0ab42a, 0xa87ff28, 0x64391992, 0x9c7d5782},
		[]uint32{0x86006c29, 0x8581a07a, 0xfeca840, 0x5b4bb151, 0x289e95f9, 0x9d8cfa2e, 0x652631b6, 0x980c3c38},
	},
	{
		[]uint32{0x9a5e6abb, 0xeb30210d, 0xc53405c7, 0x45db575a},
		[]uint32{0x5cab9b5b, 0x28d3ad76, 0x9ef3cb19, 0x582a0e6b, 0xc7985776, 0x7d61d151, 0x43a7e6a, 0x608ca738, 0x8a86b2a1},
		[]uint32{0x98b81bec, 0x910750bc, 0xabf827dc, 0x92f6c8ca, 0xfcbc5998, 0xe7372280, 0x5b9b97a6, 0xac373deb, 0x9a4974fe},
	},
}

func TestArbitrarySizeBlockEncryption(t *testing.T) {
	for n, v := range arbitrarySizeBlockTestVectors {
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
