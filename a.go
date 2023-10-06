package main

import (
	"fmt"
	"os"
)

func main() {
	name := "__$ENV$xyzzy__"

	fmt.Printf("name[0:7] ->%s<-\n", name[0:len("__$ENV$")])

	if len(name) > len("__$ENV$x") && name[0:len("__$ENV$")] == "__$ENV$" {
		fmt.Printf("lookup ->%s<-\n", name[len("__$ENV$"):len(name)-2])
		env := os.Getenv(name[len("__$ENV$") : len(name)-2])
		if env != "" {
			// return true, env
			fmt.Printf("Found name= ->%s<- : ->%s<-\n", name, env)
			return
		}
	}
	fmt.Printf("NotFound name = ->%s<-\n", name)
}
