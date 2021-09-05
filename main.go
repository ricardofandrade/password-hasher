package main

import "github.com/ricardofandrade/password-hasher/ph"

func main() {
	server := ph.NewPasswordHasherServer()
	server.Run()
}
