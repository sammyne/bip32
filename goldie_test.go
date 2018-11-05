package bip32_test

import (
	"io"
	"testing"

	"github.com/sammy00/bip32"
)

type generateMasterKeyExpect struct {
	key string
	bad bool
}

type generateMasterKeyGoldie struct {
	rand     io.Reader
	keyID    *bip32.Magic
	strength int
	expect   generateMasterKeyExpect
}

func readInGenerateMasterKeyGoldie(t *testing.T) []*generateMasterKeyGoldie {
	var golden []bip32.Goldie
	if err := bip32.ReadGoldenJSON(bip32.GoldenName, &golden); nil != err {
		t.Fatal(err)
	}

	var goods []*generateMasterKeyGoldie
	for _, v := range golden {
		// find the master private key
		var master string
		for _, k := range v.Chains {
			if childs, err := k.Path.ChildIndices(); nil != err {
				continue
			} else if 0 == len(childs) {
				master = k.ExtendedPrivateKey
				break
			}
		}

		if 0 == len(master) {
			continue
		}

		goods = append(goods, &generateMasterKeyGoldie{
			rand:     bip32.NewEntropyReader(v.Seed),
			keyID:    bip32.MainNetPrivateKey,
			strength: len(v.Seed) / 2, // divide by 2 to get the actual byte length
			expect: generateMasterKeyExpect{
				key: master,
				bad: false,
			},
		})
	}

	if 0 == len(goods) {
		t.Fatal("no good goldies")
	}

	bads := []*generateMasterKeyGoldie{
		{ // not enough entropy
			bip32.NewEntropyReader("abcd"),
			bip32.MainNetPrivateKey,
			bip32.RecommendedSeedLen,
			generateMasterKeyExpect{"", true},
		},
	}

	return append(goods, bads...)
}
