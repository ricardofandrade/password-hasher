package main

import (
	"github.com/ricardofandrade/password-hasher/ph"
	"log"
	"os"
)

func main() {
	server := ph.NewPasswordHasherServer(log.New(os.Stderr, "", log.LstdFlags))
	server.Run()
}
