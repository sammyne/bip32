package bip32

import (
	"encoding/hex"
	"io"
	"strings"
)

//type EntropyReader = io.Reader

func NewEntropyReader(hexStr string) io.Reader {
	return hex.NewDecoder(strings.NewReader(hexStr))
}

var Seeds = []string{
	"000102030405060708090a0b0c0d0e0f",
	"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
	"4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
}
