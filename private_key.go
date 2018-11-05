package bip32

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/sammy00/base58"
)

type PrivateKey struct {
	PublicKey
	Data []byte
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

func (priv *PrivateKey) Hardened() bool {
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
	if 0 == len(priv.Data) {
		return "zeroed private key"
	}

	// The serialized format is:
	//   version (4) || depth (1) || parent fingerprint (4)) ||
	//   child num (4) || chain code (32) || key data (33)
	buf := make([]byte, 0, KeyLen-VersionLen)
	buf = appendMeta(buf, &priv.PublicKey)
	buf = append(buf, 0x00)
	buf = paddedAppend(KeyDataLen-1, buf, priv.Data)

	return base58.CheckEncodeX(priv.Version, buf)
}

func (priv *PrivateKey) ToECPrivate() *btcec.PrivateKey {
	panic("not implemented")
}

func NewPrivateKey(version []byte, depth uint8, parentFP []byte, index uint32,
	chainCode, data []byte) *PrivateKey {
	pub := PublicKey{
		Version:    version,
		Level:      depth,
		ParentFP:   parentFP,
		ChildIndex: index,
		ChainCode:  chainCode,
		//Data:       data,
	}

	return &PrivateKey{PublicKey: pub, Data: data}
}

func ParsePrivateKey(data58 string) (*PrivateKey, error) {
	pub, err := decodePublicKey(data58)
	if nil != err {
		return nil, err
	}

	priv := &PrivateKey{
		PublicKey: *pub,
		Data:      pub.Data[1:],
	}

	// don't miss to nil out the public key data
	priv.PublicKey.Data = nil

	return priv, nil
}
