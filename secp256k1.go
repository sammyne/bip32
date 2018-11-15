package bip32

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

var secp256k1Curve = btcec.S256()

func ToUsableScalar(k []byte) (*big.Int, bool) {
	x := new(big.Int).SetBytes(k)

	return x, x.Cmp(secp256k1Curve.N) < 0 && 0 != x.Sign()
}
