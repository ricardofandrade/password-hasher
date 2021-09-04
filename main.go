package main

import "github.com/ricardofandrade/password-hasher/ph"

func main() {
	pwHasher := ph.NewPasswordHasher()
	pwHasher.Run()
}
