package bip32_test

import (
	"errors"
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
	bip32.ReadGoldenJSON(bip32.GoldenName, &testCases)

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

func TestPublicKey_String_Zero(t *testing.T) {
	const expect = "zeroed public key"

	if got := new(bip32.PublicKey).String(); got != expect {
		t.Fatalf("invalid string: got %s, expect %s", got, expect)
	}

}
