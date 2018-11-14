package bip32_test

import (
	"math"
	"testing"

	"github.com/sammy00/base58"
	"github.com/sammy00/bip32"
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

	for _, c := range testCases {
		c := c

		t.Run("", func(st *testing.T) {
			parent, err := bip32.ParsePrivateKey(c.parent)
			if nil != err {
				st.Fatal(err)
			}

			j := c.ChildIndex.Index
			if c.ChildIndex.Hardened {
				j = bip32.HardenIndex(j)
			}

			child, err := parent.Child(j)
			if nil != err {
				st.Fatal(err)
			}

			if got := child.String(); got != c.child {
				st.Fatalf("invalid child: got %s, expect %s", got, c.child)
			}
		})
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
