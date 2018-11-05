package bip32_test

import (
	"testing"

	"github.com/sammy00/bip32"
)

func TestParsePrivateKey_OK(t *testing.T) {
	var testCases []bip32.Goldie
	bip32.ReadGoldenJSON(bip32.GoldenName, &testCases)

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
