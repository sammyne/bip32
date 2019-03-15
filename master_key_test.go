package bip32_test

import (
	"reflect"
	"testing"

	"github.com/sammyne/bip32"
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

func TestNewMasterKey_OK(t *testing.T) {
	var testCases []*NewMasterKeyGoldie
	ReadGoldenJSON(t, bip32.GoldenName, &testCases)

	for i, c := range testCases {
		got, err := bip32.NewMasterKey(c.Seed, c.KeyID)

		if nil != err {
			t.Fatalf("#%d expects no error but got %v", i, err)
		}

		if !reflect.DeepEqual(got, c.PrivKey) {
			t.Fatalf("#%d invalid key: got %v, expect %v", i, got, c.PrivKey)
		}
	}
}

func TestNewMasterKey_Error(t *testing.T) {
	testCases := []struct {
		seed   []byte
		expect error
	}{
		{ // no error for comparison
			make([]byte, bip32.MinSeedBytes),
			nil,
		},
		{ // no error for comparison
			make([]byte, bip32.MaxSeedBytes),
			nil,
		},
		{ // seed too short
			make([]byte, bip32.MinSeedBytes-1),
			bip32.ErrInvalidSeedLen,
		},
		{ // seed too long
			make([]byte, bip32.MaxSeedBytes+1),
			bip32.ErrInvalidSeedLen,
		},
	}

	for i, c := range testCases {
		_, err := bip32.NewMasterKey(c.seed, *bip32.MainNetPrivateKey)

		if err != c.expect {
			t.Fatalf("#%d unexpected error: got %v, expect %v", i, err, c.expect)
		}
	}
}
