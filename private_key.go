package bip32

import "github.com/btcsuite/btcd/btcec"

type PrivateKey struct {
}

func (priv *PrivateKey) AddressPubKeyHash() []byte {
	panic("not implemented")
}

func (priv *PrivateKey) Child(i uint32) (ExtendedKey00, error) {
	panic("not implemented")
}

func (priv *PrivateKey) Depth() uint8 {
	panic("not implemented")
}

func (priv *PrivateKey) HardenedChild(i uint32) (ExtendedKey00, error) {
	panic("not implemented")
}

func (priv *PrivateKey) IsForNet(netID Magic) bool {
	panic("not implemented")
}

func (priv *PrivateKey) Neuter() ExtendedKey00 {
	panic("not implemented")
}

func (priv *PrivateKey) ParentFingerprint() uint32 {
	panic("not implemented")
}

func (priv *PrivateKey) Public() *btcec.PublicKey {
	panic("not implemented")
}

func (priv *PrivateKey) SetNet(netID Magic) {
	panic("not implemented")
}

func (priv *PrivateKey) String() string {
	panic("not implemented")
}

func (priv *PrivateKey) ToECPrivate() *btcec.PrivateKey {
	panic("not implemented")
}
