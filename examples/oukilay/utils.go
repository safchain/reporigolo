package main

import (
	"bytes"
	"io"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func mainAsset() io.ReaderAt {
	buf, err := Asset("main.o")
	if err != nil {
		logrus.Fatal(errors.Wrap(err, "couldn't find asset"))
	}
	return bytes.NewReader(buf)
}

func userWriteAsset() io.ReaderAt {
	buf, err := Asset("user_write.o")
	if err != nil {
		logrus.Fatal(errors.Wrap(err, "couldn't find asset"))
	}
	return bytes.NewReader(buf)
}
