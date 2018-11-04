package bip32

// masterKey is the master key used along with a random seed used to generate
// the master node in the hierarchical tree.
var masterKey = []byte("Bitcoin seed")

// masterHMACKey is the key used along with a random seed used to generate
// the master key in the hierarchical tree.
var masterHMACKey = []byte("Bitcoin seed")
