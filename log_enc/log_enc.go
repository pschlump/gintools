package log_enc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/pschlump/HashStrings"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/data"
)

var gCfg *data.GlobalConfigData

var logFilePtr *os.File = os.Stderr

func SetupLogEnc(gcfg *data.GlobalConfigData, log *os.File) {
	logFilePtr = log
	gCfg = gcfg
}

func EncryptLogData(pat string, vars ...interface{}) string {
	if gCfg.UseLogEncryption == "no" {
		return dbgo.SVar(vars)
	}
	tmp := make([]interface{}, 0, len(vars))
	i := 0
	fx := func(vi interface{}) {
		if gCfg.UseLogEncryption == "dev-dummy" {
			tmp = append(tmp, fmt.Sprintf("---Encrypted---%s---End---", vi))
		} else if gCfg.UseLogEncryption == "b64-dummy" {
			tmp = append(tmp, fmt.Sprintf("---Encrypted---%s---End---", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s", vi)))))
		} else if gCfg.UseLogEncryption == "yes" {
			tmp = append(tmp, fmt.Sprintf("---Encrypted---%s---End---", EncryptTextToB64([]byte(gCfg.LogEncryptionPassword), []byte(fmt.Sprintf("%s", vi)))))
		}
	}

	dbgo.DbPf(db8, "at:%(LF) pat ->%v<- len(pat)=%d\n", pat, len(pat))

	for _, c := range pat {

		dbgo.DbPf(db8, "at:%(LF) c ->%v<- i=%d      %(yellow)--- top of loop --\n", c, i)

		if i < len(vars) {
			switch c {
			case '.', '+':
				tmp = append(tmp, vars[i])
			case 'e':
				fx(vars[i])
			case '!': // just skip this.
				tmp = append(tmp, "---skipped---")
			}
		} else {
			tmp = append(tmp, "---To-Few-Data-Params---")
		}

		i++
	}
	for ; i < len(vars); i++ {
		fx(vars[i])
	}
	return dbgo.SVar(tmp)
}

var prefix = "Marrrry had a littttle lambb, ItS FleEse was White a gold"

func EncryptTextToB64(key, text []byte) string {

	enc, err := EncryptText(key, text)
	if err != nil {
		enc = []byte(fmt.Sprintf("%s", err))
	}

	return base64.StdEncoding.EncodeToString(enc)
}

func EncryptText(key, text []byte) ([]byte, error) {
	// use SHA256 of "key" to generate real key.  Add a "fixed salt" for hash PJS
	tkey := HashStrings.HashStrings(prefix, string(key))
	rkey := ([]byte(tkey))[0:32]
	block, err := aes.NewCipher(rkey)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize] // Generate Randome !!! PJS
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func DecryptText(key, text []byte) ([]byte, error) {
	tkey := HashStrings.HashStrings(prefix, string(key))
	rkey := ([]byte(tkey))[0:32]
	block, err := aes.NewCipher(rkey)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func EncryptTextToB64Indexable(key, iv, text []byte) string {

	enc, err := EncryptTextIndexable(key, iv, text)
	if err != nil {
		enc = []byte(fmt.Sprintf("%s", err))
	}

	return base64.StdEncoding.EncodeToString(enc)
}

func EncryptTextIndexable(key, xiv, text []byte) ([]byte, error) {
	// use SHA256 of "key" to generate real key.  Add a "fixed salt" for hash PJS
	tkey := HashStrings.HashStrings(prefix, string(key))
	rkey := ([]byte(tkey))[0:32]
	block, err := aes.NewCipher(rkey)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize] // Generate Randome !!! PJS
	for ii := 0; ii < aes.BlockSize; ii++ {
		if ii < len(xiv) {
			iv[ii] = xiv[ii]
		} else {
			iv[ii] = 0x22
		}
	}
	//	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
	//		return nil, err
	//	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

var db8 bool = false
