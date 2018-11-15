package bip32_test

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"github.com/sammy00/base58"
	"github.com/sammy00/bip32"
)

func TestParsePublicKey_Bad(t *testing.T) {
	testCases := []struct {
		xpub   string
		expect error
	}{
		{ // invalid base58 checksum: last 8=>9
			"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet9",
			base58.ErrChecksum,
		},
		{ // invalid key data length where the payload is
			"Deb7pNXSbX7qSvc3z9b2KK4Kj4CgjiaubnNEm4wriWVEKnBHZVzVzeM8feeG9zVydgrHxWsE1XfsTmUf3KSZrpXzqXQfudvgwMmu7yVuw19FeD",
			bip32.ErrInvalidKeyLen,
		},
		{ // invalid data prefix 0xff, which should be 0x02, 0x03 or 0x04
			"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2ghTzptgqt41dxzAMZBiYMF5w2RQPyuXp1yBkzwxbYKEBjawGLZqf",
			errors.New("invalid magic in compressed pubkey string: 255"),
		},
	}

	/*
		v, xpub, _ := base58.CheckDecodeX("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", bip32.VersionLen)
		t.Log(base58.CheckEncodeX(v, xpub[1:]))
	*/
	/*
		v, xpub, _ := base58.CheckDecodeX("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", bip32.VersionLen)
		xpub[bip32.KeyLen-bip32.KeyDataLen-bip32.VersionLen] = 0xff
		t.Log(base58.CheckEncodeX(v, xpub))
	*/

	for _, c := range testCases {
		c := c

		t.Run("", func(st *testing.T) {
			_, err := bip32.ParsePublicKey(c.xpub)

			if nil == err {
				st.Fatalf("expected error but got none")
			}

			if err.Error() != c.expect.Error() {
				st.Fatalf("unexpected error: got %v, expect %v", err, c.expect)
			}

		})
	}
}

func TestParsePublicKey_OK(t *testing.T) {
	var testCases []bip32.Goldie
	ReadGoldenJSON(t, bip32.GoldenName, &testCases)

	for _, c := range testCases {
		chains := c.Chains

		t.Run("", func(st *testing.T) {
			for _, chain := range chains {
				expected := chain.ExtendedPublicKey

				pub, err := bip32.ParsePublicKey(expected)
				if nil != err {
					st.Fatalf("unexpected error: %v", err)
				}

				if got := pub.String(); got != expected {
					st.Fatalf("decoding failure: got %s, expect %s", got, expected)
				}
			}
		})
	}
}

func TestPublicKey_AddressPubKeyHash(t *testing.T) {
	const mainNetPubKeyID = 0x00

	testCases := []struct {
		xpub   string
		expect string
	}{
		{
			"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			"15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma",
		},
		{
			"xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
			"1NjxqbA9aZWnh17q1UW3rB4EPu79wDXj7x",
		},
	}

	for _, c := range testCases {
		c := c

		t.Run("", func(st *testing.T) {
			pubKey, err := bip32.ParsePublicKey(c.xpub)
			if nil != err {
				st.Fatalf("unexpected error: %v", err)
			}

			got := base58.CheckEncode(pubKey.AddressPubKeyHash(), mainNetPubKeyID)
			if got != c.expect {
				st.Fatalf("invalid address: got %s, expect %s", got, c.expect)
			}
		})
	}
}

func TestPublicKey_Child_Error(t *testing.T) {
	testCases := []struct {
		pub        *bip32.PublicKey
		childIndex uint32
		expect     string // error description
	}{
		{
			&bip32.PublicKey{Level: math.MaxUint8},
			0,
			bip32.ErrDeriveBeyondMaxDepth.Error(),
		},
		{
			&bip32.PublicKey{Level: 123},
			bip32.HardenIndex(456),
			bip32.ErrDeriveHardFromPublic.Error(),
		},
		{ // invalid public key magic in data part
			&bip32.PublicKey{
				ChainCode: []byte{
					0x87, 0x3d, 0xff, 0x81, 0xc0, 0x2f, 0x52, 0x56,
					0x23, 0xfd, 0x1f, 0xe5, 0x16, 0x7e, 0xac, 0x3a,
					0x55, 0xa0, 0x49, 0xde, 0x3d, 0x31, 0x4b, 0xb4,
					0x2e, 0xe2, 0x27, 0xff, 0xed, 0x37, 0xd5, 0x08,
				},
				Data: []byte{
					0xff, // valid ones should be 0x02 or 0x03
					0x39, 0xa3, 0x60, 0x13, 0x30, 0x15, 0x97, 0xda,
					0xef, 0x41, 0xfb, 0xe5, 0x93, 0xa0, 0x2c, 0xc5,
					0x13, 0xd0, 0xb5, 0x55, 0x27, 0xec, 0x2d, 0xf1,
					0x05, 0x0e, 0x2e, 0x8f, 0xf4, 0x9c, 0x85, 0xc2,
				},
			},
			123,
			"invalid magic in compressed pubkey string: 255",
		},
	}

	/*
		xpub, _ := bip32.ParsePublicKey("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
		for i, v := range xpub.ChainCode {
			fmt.Printf("0x%02x,", v)
			if (i+1)%8 == 0 {
				fmt.Println()
			}
		}
		fmt.Println()
		for i, v := range xpub.Data {
			fmt.Printf("0x%02x,", v)
			if i%8 == 0 {
				fmt.Println()
			}
		}
		fmt.Println()
	*/

	for i, c := range testCases {
		_, err := c.pub.Child(c.childIndex)

		var errS string
		if nil != err {
			errS = err.Error()
		}

		if errS != c.expect {
			t.Fatalf("#%d unexpected error: got %v, expect %v", i, err, c.expect)
		}
	}
}

func TestPublicKey_Child_OK(t *testing.T) {
	testCases := readChildGoldie(t, true)

	for i, c := range testCases {
		parent, err := bip32.ParsePublicKey(c.parent)
		if nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		child, err := parent.Child(c.ChildIndex.Index)
		if nil != err {
			t.Fatal(err)
		}

		if got := child.String(); got != c.child {
			t.Fatalf("#%d invalid child: got %s, expect %s", i, got, c.child)
		}
	}
}

func TestPublicKey_Public(t *testing.T) {
	var testCases []bip32.Goldie
	ReadGoldenJSON(t, bip32.GoldenName, &testCases)

	for i, c := range testCases {
		for j, chain := range c.Chains {
			xpub, _ := bip32.ParsePublicKey(chain.ExtendedPublicKey)
			pub, err := xpub.Public()
			if nil != err {
				t.Fatalf("#(%d,%d) unexpected error: %v", i, j, err)
			}

			data := pub.SerializeCompressed()
			if !bytes.Equal(data, xpub.Data) {
				t.Fatalf("#(%d,%d) invalid public key data: got %x, expect %x", i, j,
					data, xpub.Data)
			}
		}
	}
}

func TestPublicKey_SetNet(t *testing.T) {
	indices := []bip32.Magic{
		*bip32.MainNetPublicKey,
		*bip32.TestNetPublicKey,
	}

	for i, id := range indices {
		xpub := new(bip32.PublicKey)
		xpub.SetNet(id)

		if !bytes.Equal(xpub.Version, id[:]) {
			t.Fatalf("#%d failed to bind key ID %x", i, id[:])
		}
	}
}

func TestPublicKey_String_Zero(t *testing.T) {
	const expect = "zeroed public key"

	if got := new(bip32.PublicKey).String(); got != expect {
		t.Fatalf("invalid string: got %s, expect %s", got, expect)
	}
}
