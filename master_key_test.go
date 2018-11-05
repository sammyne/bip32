package bip32_test

import (
	"testing"

	"github.com/sammy00/bip32"
)

func TestGenerateMasterKey(t *testing.T) {
	testCases := readInGenerateMasterKeyGoldie(t)

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

//func readInMasterPrivKey()
