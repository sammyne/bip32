package bip32_test

import (
	"io"
	"testing"

	"github.com/sammy00/bip32"
)

func TestGenerateMasterKey(t *testing.T) {
	type expect struct {
		key string
		bad bool
	}

	testCases := []struct {
		rand     io.Reader
		keyID    *bip32.Magic
		strength int
		expect   expect
	}{
		{
			bip32.NewEntropyReader(bip32.Seeds[0]),
			bip32.MainNetPrivateKey,
			len(bip32.Seeds[0]) / 2,
			expect{
				"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
				false,
			},
		},
		{
			bip32.NewEntropyReader(bip32.Seeds[1]),
			bip32.MainNetPrivateKey,
			len(bip32.Seeds[1]) / 2,
			expect{
				"xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
				false,
			},
		},
		{
			bip32.NewEntropyReader(bip32.Seeds[2]),
			bip32.MainNetPrivateKey,
			len(bip32.Seeds[2]) / 2,
			expect{
				"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
				false,
			},
		},
		{ // not enough entropy
			bip32.NewEntropyReader("abcd"),
			bip32.MainNetPrivateKey,
			bip32.RecommendedSeedLen,
			expect{"", true},
		},
	}

	for _, c := range testCases {
		c := c

		t.Run("", func(st *testing.T) {
			key, err := bip32.GenerateMasterKey(c.rand, *c.keyID, c.strength)

			if c.expect.bad && nil == err {
				st.Fatal("expect error but got none")
			} else if !c.expect.bad && nil != err {
				st.Fatalf("unexpected error: %v", err)
			}

			if c.expect.bad {
				return // skip due to error out
			}

			if got := key.String(); got != c.expect.key {
				st.Fatalf("invalid key: got %s, expect %s", got, c.expect.key)
			}
		})
	}
}
