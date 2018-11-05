package bip32

import (
	"bytes"

	"github.com/btcsuite/btcutil"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/sammy00/base58"
)

type PrivateKey struct {
	PublicKey
	Data    []byte
	Version []byte
}

func (priv *PrivateKey) AddressPubKeyHash() []byte {
	return btcutil.Hash160(priv.publicKeyData())
}

func (priv *PrivateKey) Child(i uint32) (ExtendedKey00, error) {
	panic("not implemented")
}

func (priv *PrivateKey) Depth() uint8 {
	return priv.Level
}

func (priv *PrivateKey) Hardened() bool {
	return priv.ChildIndex >= HardenedKeyStart
}

func (priv *PrivateKey) HardenedChild(i uint32) (ExtendedKey00, error) {
	panic("not implemented")
}

func (priv *PrivateKey) Index() uint32 {
	return priv.PublicKey.Index()
}

func (priv *PrivateKey) IsForNet(keyID Magic) bool {
	return bytes.Equal(priv.Version, keyID[:])
}

func (priv *PrivateKey) Neuter() (*PublicKey, error) {
	// Get the associated public extended key version bytes.
	version, err := chaincfg.HDPrivateKeyToPublicKeyID(priv.Version)
	if err != nil {
		return nil, err
	}

	pub := priv.PublicKey // copy the common part

	// and update the different parts
	pub.Version = version

	data := priv.publicKeyData()
	pub.Data = make([]byte, len(data))
	copy(pub.Data, data)

	return &pub, nil
}

func (priv *PrivateKey) ParentFingerprint() uint32 {
	return priv.PublicKey.ParentFingerprint()
}

func (priv *PrivateKey) Public() (*btcec.PublicKey, error) {
	return btcec.ParsePubKey(priv.publicKeyData(), secp256k1Curve)
}

func (priv *PrivateKey) SetNet(keyID Magic) {
	priv.Version = keyID[:]
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
	privKey, _ := btcec.PrivKeyFromBytes(secp256k1Curve, priv.Data)

	return privKey
}

func (priv *PrivateKey) publicKeyData() []byte {
	if 0 == len(priv.PublicKey.Data) {
		x, y := secp256k1Curve.ScalarBaseMult(priv.Data)
		pubKey := btcec.PublicKey{Curve: secp256k1Curve, X: x, Y: y}

		priv.PublicKey.Data = pubKey.SerializeCompressed()
	}

	return priv.PublicKey.Data
}

func NewPrivateKey(version []byte, depth uint8, parentFP []byte, index uint32,
	chainCode, data []byte) *PrivateKey {
	pub := PublicKey{
		//Version:    version,
		Level:      depth,
		ParentFP:   parentFP,
		ChildIndex: index,
		ChainCode:  chainCode,
		//Data:       data,
	}

	priv := &PrivateKey{PublicKey: pub, Data: data, Version: version}

	// derive public key eagerly
	// this should be considered more seriously
	//priv.PublicKey.Data = derivePublicKey(priv.Data)

	return priv
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
	priv.Version = priv.PublicKey.Version
	priv.PublicKey.Data, priv.PublicKey.Version = nil, nil

	// load the public key data eagerly
	/*
		x, y := secp256k1Curve.ScalarBaseMult(priv.Data)
		pubKey := btcec.PublicKey{Curve: secp256k1Curve, X: x, Y: y}
		priv.PublicKey.Data = pubKey.SerializeCompressed()
	*/
	//priv.PublicKey.Data = derivePublicKey(priv.Data)

	return priv, nil
}
