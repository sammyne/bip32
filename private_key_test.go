package bip32_test

import (
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

	for _, c := range testCases {
		c := c

		t.Run("", func(st *testing.T) {
			privKey, err := bip32.ParsePrivateKey(c.xprv)
			if nil != err {
				st.Fatalf("unexpected error: %v", err)
			}

			got := base58.CheckEncode(privKey.AddressPubKeyHash(), mainNetPubKeyID)
			if got != c.expect {
				st.Fatalf("invalid address: got %s, expect %s", got, c.expect)
			}
		})
	}
}

func TestPrivateKey_Child_OK(t *testing.T) {
	// The private extended keys for test vectors in [BIP32].
	testVec1MasterPrivKey := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	testVec2MasterPrivKey := "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"

	tests := []struct {
		name     string
		master   string
		path     []uint32
		wantPriv string
	}{
		// Test vector 1
		{
			name:     "test vector 1 chain m",
			master:   testVec1MasterPrivKey,
			path:     []uint32{},
			wantPriv: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
		},
		{
			name:     "test vector 1 chain m/0",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0},
			wantPriv: "xprv9uHRZZhbkedL37eZEnyrNsQPFZYRAvjy5rt6M1nbEkLSo378x1CQQLo2xxBvREwiK6kqf7GRNvsNEchwibzXaV6i5GcsgyjBeRguXhKsi4R",
		},
		{
			name:     "test vector 1 chain m/0/1",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1},
			wantPriv: "xprv9ww7sMFLzJMzy7bV1qs7nGBxgKYrgcm3HcJvGb4yvNhT9vxXC7eX7WVULzCfxucFEn2TsVvJw25hH9d4mchywguGQCZvRgsiRaTY1HCqN8G",
		},
		{
			name:     "test vector 1 chain m/0/1/2",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1, 2},
			wantPriv: "xprv9xrdP7iD2L1YZCgR9AecDgpDMZSTzP5KCfUykGXgjBxLgp1VFHsEeL3conzGAkbc1MigG1o8YqmfEA2jtkPdf4vwMaGJC2YSDbBTPAjfRUi",
		},
		{
			name:     "test vector 1 chain m/0/1/2/2",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1, 2, 2},
			wantPriv: "xprvA2J8Hq4eiP7xCEBP7gzRJGJnd9CHTkEU6eTNMrZ6YR7H5boik8daFtDZxmJDfdMSKHwroCfAfsBKWWidRfBQjpegy6kzXSkQGGoMdWKz5Xh",
		},
		{
			name:     "test vector 1 chain m/0/1/2/2/1000000000",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1, 2, 2, 1000000000},
			wantPriv: "xprvA3XhazxncJqJsQcG85Gg61qwPQKiobAnWjuPpjKhExprZjfse6nErRwTMwGe6uGWXPSykZSTiYb2TXAm7Qhwj8KgRd2XaD21Styu6h6AwFz",
		},

		// Test vector 2
		{
			name:     "test vector 2 chain m",
			master:   testVec2MasterPrivKey,
			path:     []uint32{},
			wantPriv: "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
		},
		{
			name:     "test vector 2 chain m/0",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0},
			wantPriv: "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
		},
		{
			name:     "test vector 2 chain m/0/2147483647",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647},
			wantPriv: "xprv9wSp6B7cXJWXZRpDbxkFg3ry2fuSyUfvboJ5Yi6YNw7i1bXmq9QwQ7EwMpeG4cK2pnMqEx1cLYD7cSGSCtruGSXC6ZSVDHugMsZgbuY62m6",
		},
		{
			name:     "test vector 2 chain m/0/2147483647/1",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647, 1},
			wantPriv: "xprv9ysS5br6UbWCRCJcggvpUNMyhVWgD7NypY9gsVTMYmuRtZg8izyYC5Ey4T931WgWbfJwRDwfVFqV3b29gqHDbuEpGcbzf16pdomk54NXkSm",
		},
		{
			name:     "test vector 2 chain m/0/2147483647/1/2147483646",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647, 1, 2147483646},
			wantPriv: "xprvA2LfeWWwRCxh4iqigcDMnUf2E3nVUFkntc93nmUYBtb9rpSPYWa8MY3x9ZHSLZkg4G84UefrDruVK3FhMLSJsGtBx883iddHNuH1LNpRrEp",
		},
		{
			name:     "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPriv: "xprvA48ALo8BDjcRET68R5RsPzF3H7WeyYYtHcyUeLRGBPHXu6CJSGjwW7dWoeUWTEzT7LG3qk6Eg6x2ZoqD8gtyEFZecpAyvchksfLyg3Zbqam",
		},

		// Custom tests to trigger specific conditions.
		{
			// Seed 000000000000000000000000000000da.
			name:     "Derived privkey with zero high byte m/0",
			master:   "xprv9s21ZrQH143K4FR6rNeqEK4EBhRgLjWLWhA3pw8iqgAKk82ypz58PXbrzU19opYcxw8JDJQF4id55PwTsN1Zv8Xt6SKvbr2KNU5y8jN8djz",
			path:     []uint32{0},
			wantPriv: "xprv9uC5JqtViMmgcAMUxcsBCBFA7oYCNs4bozPbyvLfddjHou4rMiGEHipz94xNaPb1e4f18TRoPXfiXx4C3cDAcADqxCSRSSWLvMBRWPctSN9",
		},
	}

tests:
	for i, test := range tests {
		var (
			extKey bip32.ExtendedKey00
			err    error
		)
		extKey, err = bip32.ParsePrivateKey(test.master)
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected error "+
				"creating extended key: %v", i, test.name,
				err)
			continue
		}

		for _, childNum := range test.path {
			var err error
			extKey, err = extKey.Child(childNum)
			if err != nil {
				t.Errorf("err: %v", err)
				continue tests
			}
		}

		privStr := extKey.String()
		if privStr != test.wantPriv {
			t.Errorf("Child #%d (%s): mismatched serialized "+
				"private extended key -- got: %s, want: %s", i,
				test.name, privStr, test.wantPriv)
			continue
		}
	}
}

func TestPrivateKey_Child_OK2(t *testing.T) {
	var testCases []bip32.Goldie
	bip32.ReadGoldenJSON(bip32.GoldenName, &testCases)

	for _, c := range testCases {
		c := c

		t.Run("", func(st *testing.T) {
			for _, chain := range c.Chains {
				expect := chain.ExtendedPrivateKey

				priv, err := bip32.GenerateMasterKey(bip32.NewEntropyReader(
					c.Seed), *bip32.MainNetPrivateKey, len(c.Seed)/2)
				if nil != err {
					st.Fatal(err)
				}

				indices, err := chain.Path.ChildIndices()
				if nil != err {
					st.Fatal(err)
				}

				for _, index := range indices {
					j := index.Index
					if index.Hardened {
						j = bip32.HardenIndex(j)
					}

					extKey, err := priv.Child(j)
					if nil != err {
						st.Fatal(err)
					}
					var ok bool
					if priv, ok = extKey.(*bip32.PrivateKey); !ok {
						st.Fatal("coversion failed")
					}
				}

				if got := priv.String(); got != expect {
					st.Fatalf("invalid private key: got %s, expect %s", got, expect)
				}
				/*
					childs, _ := chain.Path.ChildIndices()
					if 0 == len(childs) {
						extKey, err := bip32.GenerateMasterKey(bip32.NewEntropyReader(
							c.Seed), bip32.MainNetPrivateKey, len(c.Seed)/2)

						if nil != err {
							st.Fatal(err)
						}

						priv = bip32.ExtendedKeyToPrivateKey(extKey)
					} else {
						path := "m"
					}
				*/
			}
		})
	}
}

func TestPrivateKey_Neuter(t *testing.T) {
	var testCases []bip32.Goldie
	bip32.ReadGoldenJSON(bip32.GoldenName, &testCases)

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
