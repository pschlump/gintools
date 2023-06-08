package main

import (
	"fmt"

	"github.com/pschlump/uuid"
)

func main() {
	fmt.Printf("%s\n", GenUUID())
}

// GenUUID generates a UUID and returns it.
func GenUUID() string {
	newUUID, _ := uuid.NewV4() // Intentionally ignore errors - function will never return any.
	return newUUID.String()
}
