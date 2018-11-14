package bip32_test

import (
	"testing"

	"github.com/sammy00/bip32"
)

func TestGenerateMasterKey(t *testing.T) {
	testCases := readInGenerateMasterKeyGoldie(t)

	for i, c := range testCases {
		key, err := bip32.GenerateMasterKey(c.rand, *c.keyID, c.strength)

		if c.expect.bad && nil == err {
			t.Fatalf("#%d expect error but got none", i)
		} else if !c.expect.bad && nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		if c.expect.bad {
			return // skip due to error out
		}

		if got := key.String(); got != c.expect.key {
			t.Fatalf("#%d invalid key: got %s, expect %s", i, got, c.expect.key)
		}
	}
}
