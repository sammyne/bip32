package bip32_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sammy00/bip32"
)

func ReadGoldenJSON(t *testing.T, name string, golden interface{}) {
	fd, err := os.Open(filepath.Join(bip32.GoldenBase, name))
	if nil != err {
		t.Fatal(err)
	}
	defer fd.Close()

	if err := json.NewDecoder(fd).Decode(golden); nil != err {
		t.Fatal(err)
	}
}
