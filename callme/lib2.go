package callme

import "github.com/gofrs/uuid"

// GenUUID generates a UUID and returns it.
func GenUUID() string {
	newUUID, _ := uuid.NewV4() // Intentionally ignore errors - function will never return any.
	return newUUID.String()
}

type SQLStringType struct {
	X string
}
type SQLIntType struct {
	X *int
}
