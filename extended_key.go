package bip32

import "github.com/btcsuite/btcd/btcec"

type ExtendedKey interface {
	AddressPubKeyHash() []byte
	Child(i uint32) (ExtendedKey, error)
	Depth() uint8
	Hardened() bool
	Index() uint32
	IsForNet(keyID Magic) bool
	ParentFingerprint() uint32
	Public() (*btcec.PublicKey, error)
	SetNet(keyID Magic)
	String() string
}
