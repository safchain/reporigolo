package hidden

import (
	"bytes"
	"io"

	"github.com/safchain/reporigolo/examples/oukilay/ebpf/build"
)

func mainAsset() io.ReaderAt {
	buf, err := build.Asset("main.o")
	if err != nil {
		return nil
	}
	return bytes.NewReader(buf)
}

func overrideAsset() io.ReaderAt {
	buf, err := build.Asset("override_user.o")
	if err != nil {
		return nil
	}
	return bytes.NewReader(buf)
}

func HandleError(err error) {
	panic(err)
}
