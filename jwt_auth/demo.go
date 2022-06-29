package jwt_auth

import (
	SetDefault "github.com/pschlump/gintools/setDefault"
)

var demo struct {
	A string `default:"bob"`
}

func SetDefaultRunner() {
	SetDefault.SetDefault(&demo)
}
