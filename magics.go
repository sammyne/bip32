package bip32

const MagicLen = 4

type Magic [MagicLen]byte

// magic bytes as version prefix for serialization
var (
	MainNetPrivateKey = &Magic{0x04, 0x88, 0xad, 0xe4} // starts with xprv
	MainNetPublicKey  = &Magic{0x04, 0x88, 0xb2, 0x1e} // starts with xpub

	TestNetPrivateKey = &Magic{0x04, 0x35, 0x83, 0x94} // starts with tprv
	TestNetPublicKey  = &Magic{0x04, 0x35, 0x87, 0xcf} // starts with tpub
)
