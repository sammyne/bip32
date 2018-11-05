package bip32

import (
	"github.com/btcsuite/btcd/btcec"
)

type PublicKey struct{}

func (pub *PublicKey) AddressPubKeyHash() []byte {
	panic("not implemented")
}

func (pub *PublicKey) Child(i uint32) (ExtendedKey00, error) {
	panic("not implemented")
}

func (pub *PublicKey) Depth() uint8 {
	panic("not implemented")
}

func (pub *PublicKey) HardenedChild(i uint32) (ExtendedKey00, error) {
	panic("not implemented")
}

func (pub *PublicKey) IsForNet(netID Magic) bool {
	panic("not implemented")
}

func (pub *PublicKey) ParentFingerprint() uint32 {
	panic("not implemented")
}

func (pub *PublicKey) Public() *btcec.PublicKey {
	panic("not implemented")
}

func (pub *PublicKey) SetNet(netID Magic) {
	panic("not implemented")
}

func (pub *PublicKey) String() string {
	panic("not implemented")
}
