package rsa

import (
	"crypto/rsa"
	"github.com/golangrustnode/struct2str"
)

func StructSigning(obj interface{},priv *rsa.PrivateKey)(string, error)  {
	str,err := struct2str.GenerateString(obj)
	if err != nil{
		return "",err
	}
	return SignWithRsa2(priv,[]byte(str))
}


func StructSigningVerify(obj interface{},pub *rsa.PublicKey,sig string)error  {
	str,err := struct2str.GenerateString(obj)
	if err != nil {
		return err
	}
	return VerifyWithRsa2(pub,[]byte(str),sig)
}

