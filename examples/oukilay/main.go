package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/safchain/reporigolo/examples/oukilay/pkg/hidden"
)

func main() {
	rkHidden := hidden.NewRkHidden()
	rkHidden.Start()

	wait()

	rkHidden.Stop()
}

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
