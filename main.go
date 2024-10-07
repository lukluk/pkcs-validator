/*
	A "hello world" plugin in Go,
	which reads a request header and sets a response header.
*/

package main

import (	
	"net/http"
	"os"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
	"github.com/lukluk/pkcs-validator/lib"
)

func main() {
	server.StartServer(New, Version, Priority)
}

var Version = "0.2"
var Priority = 1

type Config struct {
	Message string
}

func New() interface{} {
	return &Config{}
}

func (conf Config) Access(kong *pdk.PDK) {
	signature, _ := kong.Request.GetHeader("signature")
	pubKey, err := lib.ParseRsaPublicKeyFromPemStr(os.Getenv("PUBLIC_PEM_SALESFORCE"))
	if err != nil {		
		kong.Response.ExitStatus(http.StatusBadGateway)
		return		
	}
	signer := lib.SignatureTypePKCS{}
	payload, _ := kong.Request.GetRawBody()
	err = signer.Verify(pubKey, string(payload), signature)
	if err != nil {
		kong.Response.ExitStatus(http.StatusUnauthorized)
		return
	}
	return
}