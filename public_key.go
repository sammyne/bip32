package bip32

import (
	"encoding/binary"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"github.com/sammy00/base58"
)

type PublicKey struct {
	ChainCode  []byte
	ChildIndex uint32 // this is the Index-th child of its parent
	Data       []byte
	Level      uint8 // name so to avoid conflict with method Depth()
	ParentFP   []byte
	Version    []byte
}

func (pub *PublicKey) AddressPubKeyHash() []byte {
	return btcutil.Hash160(pub.Data)
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
	if 0 == len(pub.Data) {
		return "zeroed public key"
	}

	var childIndex [ChildIndexLen]byte
	binary.BigEndian.PutUint32(childIndex[:], pub.ChildIndex)

	// The serialized format is:
	//   version (4) || depth (1) || parent fingerprint (4)) ||
	//   child num (4) || chain code (32) || key data (33)
	str := make([]byte, 0, KeyLen-VersionLen)
	//str = append(str, pub.Version...)
	str = append(str, pub.Level)
	str = append(str, pub.ParentFP...)
	str = append(str, childIndex[:]...)
	str = append(str, pub.ChainCode...)
	str = append(str, pub.Data...)

	//return base58.CheckEncode()
	return base58.CheckEncodeX(pub.Version, str)
}

func NewPublicKey(data []byte) *PublicKey {
	return &PublicKey{Data: data}
}

func ParsePublicKey(data58 string) (*PublicKey, error) {
	version, decoded, err := base58.CheckDecodeX(data58, VersionLen)
	if nil != err {
		return nil, err
	}

	if KeyLen != len(decoded)+VersionLen {
		return nil, ErrInvalidKeyLen
	}

	pub := new(PublicKey)
	// The serialized format is:
	//   version (4) || depth (1) || parent fingerprint (4)) ||
	//   child num (4) || chain code (32) || key data (33)
	// where the version has separated from decoded

	// decompose the decoded payload into fields
	//a, b := 0, VersionLen
	//pub.Version = decoded[a:b]
	pub.Version = version

	//a, b = b, b+DepthLen
	a, b := 0, DepthLen
	pub.Level = decoded[a:b][0]

	a, b = b, b+FingerprintLen
	pub.ParentFP = decoded[a:b]

	a, b = b, b+ChildIndexLen
	pub.ChildIndex = binary.BigEndian.Uint32(decoded[a:b])

	a, b = b, b+ChainCodeLen
	pub.ChainCode = decoded[a:b]

	a, b = b, b+KeyDataLen
	pub.Data = decoded[a:b]

	// on-curve checking
	if _, err := btcec.ParsePubKey(pub.Data, secp256k1Curve); nil != err {
		return nil, err
	}

	return pub, nil
}
