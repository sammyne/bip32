package bip32

import (
	"bytes"
	"testing"
)

func TestReverseCopy(t *testing.T) {
	testCases := []struct {
		dst, src []byte
		expect   []byte
	}{
		{
			make([]byte, 4),
			[]byte{0x12, 0x34},
			[]byte{0x00, 0x00, 0x12, 0x34},
		},
		{
			make([]byte, 2),
			[]byte{0x12, 0x34, 0x56},
			[]byte{0x34, 0x56},
		},
	}

	for i, c := range testCases {
		ReverseCopy(c.dst, c.src)

		if !bytes.Equal(c.dst, c.expect) {
			t.Fatalf("#%d failed: got %v, expect %v", i, c.dst, c.expect)
		}
	}
}

func TestPaddedAppend(t *testing.T) {
	dst := make([]byte, 0, 12)
	src := []byte{0x12, 0x34}

	hello := paddedAppend(3, dst, src)
	t.Logf("% x", dst)
	t.Logf("% x", hello)
}
