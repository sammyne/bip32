package bip32

import "testing"

func TestReverseCopy(t *testing.T) {
	dst := make([]byte, 12)
	src := []byte{0x12, 0x34}

	ReverseCopy(dst, src)
	t.Logf("% x", dst)
}

func TestPaddedAppend(t *testing.T) {
	dst := make([]byte, 0, 12)
	src := []byte{0x12, 0x34}

	hello := paddedAppend(3, dst, src)
	t.Logf("% x", dst)
	t.Logf("% x", hello)
}
