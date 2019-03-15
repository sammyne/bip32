package bip32_test

import (
	"bytes"
	"math"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"

	"github.com/sammyne/base58"
	"github.com/sammyne/bip32"
)

func TestPrivateKey_AddressPubKeyHash(t *testing.T) {
	const mainNetPubKeyID = 0x00

	testCases := []struct {
		xprv   string
		expect string
	}{
		{ // test vector 1 - Chain m
			"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
			"15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma",
		},
		{ // test vector 1 - Chain m/0H/1/2H
			"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
			"1NjxqbA9aZWnh17q1UW3rB4EPu79wDXj7x",
		},
	}

	for i, c := range testCases {

		privKey, err := bip32.ParsePrivateKey(c.xprv)
		if nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		got := base58.CheckEncode(privKey.AddressPubKeyHash(), mainNetPubKeyID)
		if got != c.expect {
			t.Fatalf("#%d invalid address: got %s, expect %s", i, got, c.expect)
		}
	}
}

func TestPrivateKey_Child_Error(t *testing.T) {
	testCases := []struct {
		priv       *bip32.PrivateKey
		childIndex uint32
		expect     error
	}{
		{
			&bip32.PrivateKey{PublicKey: bip32.PublicKey{Level: math.MaxUint8}},
			0,
			bip32.ErrDeriveBeyondMaxDepth,
		},
	}

	for i, c := range testCases {
		_, got := c.priv.Child(c.childIndex)

		if got != c.expect {
			t.Fatalf("#%d unexpected error: got %v, expect %v", i, got, c.expect)
		}
	}
}

func TestPrivateKey_Child_OK(t *testing.T) {
	testCases := readChildGoldie(t, false)

	for i, c := range testCases {
		//c := c

		//t.Run("", func(st *testing.T) {
		parent, err := bip32.ParsePrivateKey(c.parent)
		if nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		j := c.ChildIndex.Index
		if c.ChildIndex.Hardened {
			j = bip32.HardenIndex(j)
		}

		child, err := parent.Child(j)
		if nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		if got := child.String(); got != c.child {
			t.Fatalf("#%d invalid child: got %s, expect %s", i, got, c.child)
		}
		//})
	}
}

func TestPrivateKey_Neuter(t *testing.T) {
	var testCases []bip32.Goldie
	ReadGoldenJSON(t, bip32.GoldenName, &testCases)

	for _, c := range testCases {
		chains := c.Chains

		t.Run("", func(st *testing.T) {
			for _, chain := range chains {
				expect := chain.ExtendedPublicKey

				priv, err := bip32.ParsePrivateKey(chain.ExtendedPrivateKey)
				if nil != err {
					st.Fatalf("unexpected error: %v", err)
				}

				pub, err := priv.Neuter()
				if nil != err {
					st.Fatalf("unexpected error: %v", err)
				}

				if got := pub.String(); got != expect {
					st.Fatalf("invalid neutered public key: got %s, expect %s",
						got, expect)
				}
			}
		})
	}
}

func TestPrivateKey_Neuter_Error(t *testing.T) {
	xprv, _ := bip32.ParsePrivateKey("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")

	testCases := []struct {
		priv   *bip32.PrivateKey
		expect error
	}{
		{ // good key for comparison
			xprv, nil,
		},
		{ // corrupted version
			&bip32.PrivateKey{Version: []byte{0x12, 0x34, 0x56, 0x78}},
			chaincfg.ErrUnknownHDKeyID,
		},
	}

	for i, c := range testCases {
		_, got := c.priv.Neuter()
		if got != c.expect {
			t.Fatalf("#%d unexpected error: got %v, expect %v", i, got, c.expect)
		}
	}
}

func TestPrivateKey_ParentFingerprint(t *testing.T) {
	testCases := []struct {
		priv   *bip32.PrivateKey
		expect uint32
	}{
		{
			&bip32.PrivateKey{
				PublicKey: bip32.PublicKey{ParentFP: []byte{0x12, 0x34, 0x56, 0x78}},
			},
			0x12345678,
		},
		{
			&bip32.PrivateKey{
				PublicKey: bip32.PublicKey{ParentFP: []byte{0x00, 0x34, 0x56, 0x78}},
			},
			0x00345678,
		},
		{
			&bip32.PrivateKey{
				PublicKey: bip32.PublicKey{ParentFP: []byte{0x12, 0x34, 0x56, 0x00}},
			},
			0x12345600,
		},
	}

	for i, c := range testCases {
		if got := c.priv.ParentFingerprint(); got != c.expect {
			t.Fatalf("#%d invalid parent fingerprint: got %d, expect %d", i, got,
				c.expect)
		}
	}
}

func TestPrivateKey_Public(t *testing.T) {
	var testCases []bip32.Goldie
	ReadGoldenJSON(t, bip32.GoldenName, &testCases)

	for i, c := range testCases {
		for j, chain := range c.Chains {
			priv, _ := bip32.ParsePrivateKey(chain.ExtendedPrivateKey)
			pub, err := priv.Public()
			if nil != err {
				t.Fatalf("#(%d,%d) unexpected error: %v", i, j, err)
			}

			data := pub.SerializeCompressed()
			if !bytes.Equal(data, priv.PublicKey.Data) {
				t.Fatalf("#(%d,%d) invalid public key data: got %x, expect %x", i, j,
					data, priv.PublicKey.Data)
			}
		}
	}
}

func TestPrivateKey_SetNet(t *testing.T) {
	indices := []bip32.Magic{
		*bip32.MainNetPrivateKey,
		*bip32.MainNetPublicKey,
		*bip32.TestNetPrivateKey,
		*bip32.TestNetPublicKey,
	}

	for i, id := range indices {
		priv := new(bip32.PrivateKey)
		priv.SetNet(id)

		if !bytes.Equal(priv.Version, id[:]) {
			t.Fatalf("#%d failed to bind key ID %x", i, id[:])
		}
	}
}

func TestPrivateKey_String(t *testing.T) {
	testCases := []struct {
		priv   *bip32.PrivateKey
		expect string
	}{
		{
			&bip32.PrivateKey{
				PublicKey: bip32.PublicKey{
					ChainCode: []byte{
						0x87, 0x3d, 0xff, 0x81, 0xc0, 0x2f, 0x52, 0x56,
						0x23, 0xfd, 0x1f, 0xe5, 0x16, 0x7e, 0xac, 0x3a,
						0x55, 0xa0, 0x49, 0xde, 0x3d, 0x31, 0x4b, 0xb4,
						0x2e, 0xe2, 0x27, 0xff, 0xed, 0x37, 0xd5, 0x8,
					},
					ChildIndex: 0x0,
					Data:       nil,
					Level:      0x00,
					ParentFP:   []uint8{0x0, 0x0, 0x0, 0x0},
					Version:    []uint8(nil),
				},
				Data: []byte{
					0xe8, 0xf3, 0x2e, 0x72, 0x3d, 0xec, 0xf4, 0x5,
					0x1a, 0xef, 0xac, 0x8e, 0x2c, 0x93, 0xc9, 0xc5,
					0xb2, 0x14, 0x31, 0x38, 0x17, 0xcd, 0xb0, 0x1a,
					0x14, 0x94, 0xb9, 0x17, 0xc8, 0x43, 0x6b, 0x35,
				},
				Version: []byte{0x4, 0x88, 0xad, 0xe4},
			},
			"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
		},
		{new(bip32.PrivateKey), "zeroed private key"},
	}

	for i, c := range testCases {
		if got := c.priv.String(); got != c.expect {
			t.Fatalf("#%d failed: got %s, expect %s", i, got, c.expect)
		}
	}
}

func TestParsePrivateKey_OK(t *testing.T) {
	var testCases []bip32.Goldie
	ReadGoldenJSON(t, bip32.GoldenName, &testCases)

	for _, c := range testCases {
		chains := c.Chains

		t.Run("", func(st *testing.T) {
			for _, chain := range chains {
				expect := chain.ExtendedPrivateKey

				priv, err := bip32.ParsePrivateKey(expect)
				if nil != err {
					st.Fatalf("unexpected error: %v", err)
				}

				if got := priv.String(); got != expect {
					st.Fatalf("decoding failure: got %s, expect %s", got, expect)
				}
			}
		})
	}
}

func TestParsePrivateKey_Error(t *testing.T) {
	testCases := []struct {
		xpub   string
		expect error
	}{
		{ // ok for comparsion
			"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
			nil,
		},
		{ // invalid base58 checksum: i=>j
			"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHj",
			base58.ErrChecksum,
		},
	}

	for i, c := range testCases {
		_, err := bip32.ParsePrivateKey(c.xpub)

		if err != c.expect {
			t.Fatalf("#%d unexpected error: got %v, expect %v", i, err, c.expect)
		}
	}
}
