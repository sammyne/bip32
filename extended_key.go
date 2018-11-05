package bip32

import "github.com/btcsuite/btcd/btcec"

type ExtendedKey00 interface {
	AddressPubKeyHash() []byte
	Child(i uint32) (ExtendedKey00, error)
	Depth() uint8
	HardenedChild(i uint32) (ExtendedKey00, error)
	IsForNet(netID Magic) bool
	ParentFingerprint() uint32
	Public() *btcec.PublicKey
	SetNet(netID Magic)
	String() string
}
