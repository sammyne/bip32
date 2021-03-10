package bip32

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

var curve = btcec.S256()

type ECPrivateKey = btcec.PrivateKey
type ECPublicKey = btcec.PublicKey

func DeriveECPublicKey(priv []byte) *ECPublicKey {
	return NewECPublicKey(curve.ScalarBaseMult(priv))
}

func NewECPublicKey(x, y *big.Int) *ECPublicKey {
	return &btcec.PublicKey{Curve: curve, X: x, Y: y}
}

func ParseECPrivateKey(priv []byte) (*ECPrivateKey, *ECPublicKey) {
	return btcec.PrivKeyFromBytes(curve, priv)
}

func ParseECPublicKey(pub []byte) (*ECPublicKey, error) {
	return btcec.ParsePubKey(pub, curve)
}

// ToUsableScalar tries to covert k to a scalar 0<s<secp256k1Curve.N as a big
// integer, and returns false in case of failure.
// @TODO: un-exported this.
func ToUsableScalar(k []byte) (*big.Int, bool) {
	x := new(big.Int).SetBytes(k)

	return x, x.Cmp(curve.N) < 0 && 0 != x.Sign()
}
