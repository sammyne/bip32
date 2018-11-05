package bip32

import (
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"
)

//go:generate go run golden.go

const GoldenBase = "testdata"

var Seeds = []string{
	"000102030405060708090a0b0c0d0e0f",
	"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
	"4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
}

type ChainGoldie struct {
	Path               Path // child stemming from master node
	ExtendedPublicKey  string
	ExtendedPrivateKey string
}

type ChildIndex struct {
	Index    uint32
	Hardened bool
}

type Goldie struct {
	Seed   string
	Chains []ChainGoldie
}

//type Path []ChildIndex
type Path string

func (path Path) ChildIndices() ([]*ChildIndex, error) {
	indices := strings.Split(string(path), "/")
	if len(indices) == 0 {
		return nil, errors.New("empty path isn't allowed")
	}

	childs := make([]*ChildIndex, len(indices)-1)
	for i, v := range indices[1:] { // skip the root
		hardened := strings.HasSuffix(v, "H")

		index, err := strconv.Atoi(strings.TrimSuffix(v, "H"))
		if nil != err {
			return nil, err
		}

		childs[i] = &ChildIndex{Index: uint32(index), Hardened: hardened}
	}

	return childs, nil
}

func NewEntropyReader(hexStr string) io.Reader {
	return hex.NewDecoder(strings.NewReader(hexStr))
}
