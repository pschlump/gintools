package main

// From: https://github.com/anaskhan96/go-vapidkeys

import (
	"fmt"
	"log"

	"github.com/anaskhan96/go-vapidkeys"
)

func main() {
	privateKey, publicKey, err := vapidkeys.Generate()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Vapid Private Key:", privateKey)
	fmt.Println("Vapid Public Key:", publicKey)
}
