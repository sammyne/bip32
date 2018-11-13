package bip32

import (
	"reflect"
	"testing"

	"github.com/sammy00/base58"
)

func Test_decodePublicKey(t *testing.T) {
	type expect struct {
		pub *PublicKey
		err error
	}
	testCases := []struct {
		data   string
		expect expect
	}{
		{ // no error
			"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			expect{
				&PublicKey{
					ChainCode: []byte{
						0x87, 0x3d, 0xff, 0x81, 0xc0, 0x2f, 0x52, 0x56,
						0x23, 0xfd, 0x1f, 0xe5, 0x16, 0x7e, 0xac, 0x3a,
						0x55, 0xa0, 0x49, 0xde, 0x3d, 0x31, 0x4b, 0xb4,
						0x2e, 0xe2, 0x27, 0xff, 0xed, 0x37, 0xd5, 0x8,
					},
					ChildIndex: 0x0,
					Data: []byte{
						0x3, 0x39, 0xa3, 0x60, 0x13, 0x30, 0x15, 0x97,
						0xda, 0xef, 0x41, 0xfb, 0xe5, 0x93, 0xa0, 0x2c,
						0xc5, 0x13, 0xd0, 0xb5, 0x55, 0x27, 0xec, 0x2d,
						0xf1, 0x5, 0xe, 0x2e, 0x8f, 0xf4, 0x9c, 0x85,
						0xc2,
					},
					Level:    0x0,
					ParentFP: []byte{0x0, 0x0, 0x0, 0x0},
					Version:  []byte{0x4, 0x88, 0xb2, 0x1e},
				},
				nil,
			},
		},
		{ // base58 decoding failure: last 8->9
			"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet9",
			expect{nil, base58.ErrChecksum},
		},
		{ // invalid key length: append a 0xff the public key data
			"5FQT7TT6bZmQ6QjZkciSR3iW58jYrY1rhLE3ozYsiUF7K4LwZQpHenGJQ2TxRaL3LJU44DYwWYtx9hCtKjJviZDe3oQfLFfWMm75bUsH21iGB5AmT",
			expect{nil, ErrInvalidKeyLen},
		},
	}

	for i, c := range testCases {
		pub, err := decodePublicKey(c.data)

		if err != c.expect.err {
			t.Fatalf("#%d unexpected error: got %v, expect %v", i, err, c.expect.err)
		}

		/*
			if 0 == i {
				pub.Data = append(pub.Data, 0xff)
				t.Log(pub.String())
			}*/

		if nil == err && !reflect.DeepEqual(pub, c.expect.pub) {
			t.Fatalf("#%d invalid public key: got %#v, expect %#v", i, pub,
				c.expect.pub)
		}
	}
}
