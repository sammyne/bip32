// +build ignore

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sammy00/bip32"
)

// Goldie is an alias to ease typing
type Goldie = bip32.Goldie

// ChainGoldie is an alias to ease typing
type ChainGoldie = bip32.ChainGoldie

func main() {
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

		/*
			// Custom tests to trigger specific conditions.
			{
				// Seed 000000000000000000000000000000da.
				name:     "Derived privkey with zero high byte m/0",
				master:   "xprv9s21ZrQH143K4FR6rNeqEK4EBhRgLjWLWhA3pw8iqgAKk82ypz58PXbrzU19opYcxw8JDJQF4id55PwTsN1Zv8Xt6SKvbr2KNU5y8jN8djz",
				path:     []uint32{0},
				wantPriv: "xprv9uC5JqtViMmgcAMUxcsBCBFA7oYCNs4bozPbyvLfddjHou4rMiGEHipz94xNaPb1e4f18TRoPXfiXx4C3cDAcADqxCSRSSWLvMBRWPctSN9",
			},
		*/
	}

	seeds := map[string]string{
		"test vector 1 chain": "000102030405060708090a0b0c0d0e0f",
		"test vector 2 chain": "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
	}

	// convert to Goldie
	goldens := make(map[string]*Goldie)
	for _, c := range tests {
		j := strings.LastIndex(c.name, " ")
		name, path := c.name[:j], c.name[j+1:]

		goldie, ok := goldens[name]
		if !ok {
			goldie = &Goldie{Seed: seeds[name]}
		}

		priv, err := bip32.ParsePrivateKey(c.wantPriv)
		if nil != err {
			panic(err)
		}
		pub, err := priv.Neuter()
		if nil != err {
			panic(err)
		}

		chain := ChainGoldie{
			Path:               bip32.Path(path),
			ExtendedPrivateKey: c.wantPriv,
			ExtendedPublicKey:  pub.String(),
		}
		goldie.Chains = append(goldie.Chains, chain)

		goldens[name] = goldie
	}

	goldens["test vector 4 chain"] = oneMore()

	/*
		out, err := json.MarshalIndent(goldens, "", "  ")
		if nil != err {
			panic(err)
		}
		fmt.Printf("%s\n", out)
	*/

	//_ = out
	//checkPubKey(goldens)

	names := make([]string, 0, len(goldens))
	for k := range goldens {
		names = append(names, k)
	}
	sort.Strings(names)

	goldies := make([]*Goldie, 0, len(goldens))
	for _, name := range names {
		goldies = append(goldies, goldens[name])
	}

	goldenPath := filepath.Join(bip32.GoldenBase, "bip32_addon.golden")
	fd, err := os.OpenFile(goldenPath, os.O_CREATE|os.O_WRONLY, 0600)
	if nil != err {
		panic(err)
	}
	defer fd.Close()

	encoder := json.NewEncoder(fd)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(goldies); nil != err {
		panic(err)
	}
}

func oneMore() *Goldie {
	goldie := &Goldie{
		Seed: " 000000000000000000000000000000da",
		Chains: []ChainGoldie{
			{
				Path:               "m",
				ExtendedPrivateKey: "xprv9s21ZrQH143K4FR6rNeqEK4EBhRgLjWLWhA3pw8iqgAKk82ypz58PXbrzU19opYcxw8JDJQF4id55PwTsN1Zv8Xt6SKvbr2KNU5y8jN8djz",
			},
			{
				Path:               "m/0",
				ExtendedPrivateKey: "xprv9uC5JqtViMmgcAMUxcsBCBFA7oYCNs4bozPbyvLfddjHou4rMiGEHipz94xNaPb1e4f18TRoPXfiXx4C3cDAcADqxCSRSSWLvMBRWPctSN9",
			},
		},
	}

	for i := range goldie.Chains {
		priv, err := bip32.ParsePrivateKey(goldie.Chains[i].ExtendedPrivateKey)
		if nil != err {
			panic(err)
		}

		pub, err := priv.Neuter()
		if nil != err {
			panic(err)
		}

		goldie.Chains[i].ExtendedPublicKey = pub.String()
	}

	return goldie
}

func checkPubKey(goldens map[string]*Goldie) {
	// The public extended keys for test vectors in [BIP32].
	testVec1MasterPubKey := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	testVec2MasterPubKey := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"

	tests := []struct {
		name    string
		master  string
		path    []uint32
		wantPub string
	}{
		// Test vector 1
		{
			name:    "test vector 1 chain m",
			master:  testVec1MasterPubKey,
			path:    []uint32{},
			wantPub: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		},
		{
			name:    "test vector 1 chain m/0",
			master:  testVec1MasterPubKey,
			path:    []uint32{0},
			wantPub: "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1",
		},
		{
			name:    "test vector 1 chain m/0/1",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1},
			wantPub: "xpub6AvUGrnEpfvJBbfx7sQ89Q8hEMPM65UteqEX4yUbUiES2jHfjexmfJoxCGSwFMZiPBaKQT1RiKWrKfuDV4vpgVs4Xn8PpPTR2i79rwHd4Zr",
		},
		{
			name:    "test vector 1 chain m/0/1/2",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2},
			wantPub: "xpub6BqyndF6rhZqmgktFCBcapkwubGxPqoAZtQaYewJHXVKZcLdnqBVC8N6f6FSHWUghjuTLeubWyQWfJdk2G3tGgvgj3qngo4vLTnnSjAZckv",
		},
		{
			name:    "test vector 1 chain m/0/1/2/2",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2, 2},
			wantPub: "xpub6FHUhLbYYkgFQiFrDiXRfQFXBB2msCxKTsNyAExi6keFxQ8sHfwpogY3p3s1ePSpUqLNYks5T6a3JqpCGszt4kxbyq7tUoFP5c8KWyiDtPp",
		},
		{
			name:    "test vector 1 chain m/0/1/2/2/1000000000",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2, 2, 1000000000},
			wantPub: "xpub6GX3zWVgSgPc5tgjE6ogT9nfwSADD3tdsxpzd7jJoJMqSY12Be6VQEFwDCp6wAQoZsH2iq5nNocHEaVDxBcobPrkZCjYW3QUmoDYzMFBDu9",
		},

		// Test vector 2
		{
			name:    "test vector 2 chain m",
			master:  testVec2MasterPubKey,
			path:    []uint32{},
			wantPub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
		},
		{
			name:    "test vector 2 chain m/0",
			master:  testVec2MasterPubKey,
			path:    []uint32{0},
			wantPub: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
		},
		{
			name:    "test vector 2 chain m/0/2147483647",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647},
			wantPub: "xpub6ASAVgeWMg4pmutghzHG3BohahjwNwPmy2DgM6W9wGegtPrvNgjBwuZRD7hSDFhYfunq8vDgwG4ah1gVzZysgp3UsKz7VNjCnSUJJ5T4fdD",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1},
			wantPub: "xpub6CrnV7NzJy4VdgP5niTpqWJiFXMAca6qBm5Hfsry77SQmN1HGYHnjsZSujoHzdxf7ZNK5UVrmDXFPiEW2ecwHGWMFGUxPC9ARipss9rXd4b",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1/2147483646",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1, 2147483646},
			wantPub: "xpub6FL2423qFaWzHCvBndkN9cbkn5cysiUeFq4eb9t9kE88jcmY63tNuLNRzpHPdAM4dUpLhZ7aUm2cJ5zF7KYonf4jAPfRqTMTRBNkQL3Tfta",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPub: "xpub6H7WkJf547AiSwAbX6xsm8Bmq9M9P1Gjequ5SipsjipWmtXSyp4C3uwzewedGEgAMsDy4jEvNTWtxLyqqHY9C12gaBmgUdk2CGmwachwnWK",
		},
	}

	prev, k := "", 0
	for _, c := range tests {
		j := strings.LastIndex(c.name, " ")
		//name, path := c.name[:j], c.name[j+1:]
		name := c.name[:j]

		goldie, ok := goldens[name]
		if !ok {
			//goldie = &Goldie{Seed: seeds[name]}
			panic("missing")
		}

		k++
		if name != prev {
			k, prev = 0, name
		}

		//fmt.Println("k =", k, "len(chains) =", len(goldie.Chains))
		priv, err := bip32.ParsePrivateKey(goldie.Chains[k].ExtendedPrivateKey)
		if nil != err {
			panic(err)
		}

		pub, err := priv.Neuter()
		if nil != err {
			panic(err)
		}

		if got := pub.String(); got != c.wantPub {
			fmt.Printf("invalid pub: got %s, expect %s", got, c.wantPub)
		}
	}
}
