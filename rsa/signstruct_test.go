package rsa

import (
	"testing"
)

type User struct {
	Name string
	Age int
	Id string
	Signature string
	KKK string
}


func TestStructSigning(t *testing.T) {
	privateKey, err := GeneraRsa2Key()
	if err != nil {
		t.Fatal(err)
	}
	u := &User{"TangXiaodong", 100, "0000123","FUCK","Fkdas"}
	sig,err:=StructSigning(u,privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err :=StructSigningVerify(u,&privateKey.PublicKey,sig);err != nil {
		t.Fatal(err)
	}
	t.Log("success")
}
