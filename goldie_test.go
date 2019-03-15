package bip32_test

import (
	"io"
	"testing"

	"github.com/sammyne/bip32"
)

type childGoldie struct {
	parent string
	//index      uint32
	ChildIndex *bip32.ChildIndex
	child      string // the expected child string
}

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
	ReadGoldenJSON(t, bip32.GoldenName, &golden)

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

func readChildGoldie(t *testing.T, pub bool) []*childGoldie {
	var goldens, addOn []*bip32.Goldie

	if !pub {
		ReadGoldenJSON(t, bip32.GoldenName, &goldens)
	}
	ReadGoldenJSON(t, bip32.GoldenAddOnName, &addOn)

	goldens = append(goldens, addOn...)

	var goldies []*childGoldie
	for _, v := range goldens {
		var parent string

		if pub {
			parent = v.Chains[0].ExtendedPublicKey
		} else {
			parent = v.Chains[0].ExtendedPrivateKey
		}

		for _, child := range v.Chains[1:] {
			indices, err := child.Path.ChildIndices()
			if nil != err {
				t.Fatal(err)
			}

			goldie := &childGoldie{
				parent: parent,
				//index:  indices[len(indices)-1].Index,
				ChildIndex: indices[len(indices)-1],
			}

			if pub {
				goldie.child = child.ExtendedPublicKey
			} else {
				goldie.child = child.ExtendedPrivateKey
			}
			parent = goldie.child

			goldies = append(goldies, goldie)
		}
	}

	return goldies
}
