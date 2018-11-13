package bip32

// HardenIndex maps an index in range [0,HardenedKeyStart) to
// its harhened corresponding one.
// Note: No overflow checking is implemented now.
func HardenIndex(i uint32) uint32 {
	/* if i > math.MaxUint32-HardenedKeyStart { } */
	return i + HardenedKeyStart
}

/*
func ExtendedKeyToPrivateKey(k *ExtendedKey) *PrivateKey {
	return NewPrivateKey(k.version, k.depth, k.parentFP, k.childNum,
		k.chainCode, k.key)
}
*/
