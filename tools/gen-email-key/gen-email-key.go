package main

//
// Generate HMAC key for usage of email.
//
// The code in the sever performs the following check to validate the send of an email.
//
//	 	if HashStrings.HashStrings(os.Getenv(TEST_SEND_EMAIL_PASSWORD)+pp.AuthKey== "vuO3_xzWpdUhaa8vzxygaLy7flm=" {
//
// (data is a sample!)
//
// This code is used to generat the value for "TEST_SEND_EMAIL_PASSWORD".
//

import (
	"os"

	"github.com/pschlump/HashStrings"
	"github.com/pschlump/dbgo"
)

func main() {

	password := os.Getenv("TEST_SEND_EMAIL_PASSWORD")
	key := os.Getenv("TEST_SEND_EMAIL_KEY")
	result := HashStrings.HashStrings(password + key)

	dbgo.Printf(`

Given  TEST_SEND_EMAIL_PASSWORD = ->%s<-
  And  TEST_SEND_EMAIL_KEY  = ->%s<- This is what you send as an authorization the action.

  The PASSWORD (HMAC) to use in code is ->%s<- (stored in pp.AuthKey, cfg.json "auth_key")

`, password, key, result)

}
