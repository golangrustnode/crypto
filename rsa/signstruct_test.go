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

func TestStructSigningWithPem(t *testing.T) {
	privatekey:=`
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA5/RxR0Gk6jKrvmGmOmEOG/AThlv4wUjosZXmHxaJgfpYyoSq
/VP+eXnSigrXmYLVJBknbQglk0Z+uku5n9QMKi+Ih6NQAkXxkE0xGb8CWuC6vGfY
rkBmi8/UTqeberGx1he1RYw90PpSg4V2n2SamZqfTcr0cV6lB5FSSzXBmTuSG9oD
jmxTg2yw933DB6OiJOZhHBroIsutG5tR0zfAYgLD4CR9l1GtDweWelm0pdinhtSG
0xnUtH7dRE4KjE64TgUm6ajpH/+satnrJDHUY4fpOACBBhK+i9fKKVIn1KSZ17zs
d0LTrZhNKIKtoA+bVyOi4rT/9Bx/VUHeSkcvuwIDAQABAoIBAQDA+9FblbQd3jah
2SCyJZnViLLV8KNQPNbNGYgyiU+ywpUpOaQBzOZGLyMKEuc6I24t8Heq8UJB/D7n
xKUV4xiT6KRRJYElwweuJWsanp7Y+Wyj4EqY/5/R5wIexrhHJpxtIaCB0qKDwiDw
qBP/nXY7Ijg0Qw2JXVM0rqWnSXxffWkCeftY6C1jeIixG2z8fuf8/VND5WhwzL32
cowNwOrg6gYkoN1rgXu3/2bQyhF9kZBs6fAidwb8b8+YpOKEmloFco5vqqhsOKWC
WmfhblTUcgpBqQTYisXRAhWpevS6OdZGwlzavIvtfSWzugClp5VIwpFZrruf2ifX
j/6mECqhAoGBAPmYDaSREvxepy/xTeC4StY/uRHXdPBqSgb6WwtgbkAPvbBpb6pY
oy4T/F1w8P4Sw2uhrWlgtwSEccQVpVUEt89iTpu+1QiutIWTpc63YgtRQe3MKdmQ
mrNk6vFDSgcKHTtsVOnRtH1TiHiI/2YNgEwHNWctiidASxwE9Lcs+U4ZAoGBAO3o
fgC4Fyh+5bE0vgBgjMSXHJNP1opmtFeRQx419Dt0rhRhf7vaQrPIe5R1AUy0LYQ+
MlTHwSqsIvB72iH3y80GIkQ0tc85/aEHOXi9MtbomxSdtlc5JjU4aOx8+S2fKb0W
PsfU9al0CfmYzOLbVzptXnZRqTYQiTVVBBQleD7zAoGBAOmXQ9VrrOAiWcgFxwP0
lp2TP8qR4bCLWULUlda85hHwaXAsDUTY9cdPDxYIeJLgzqHxy1DfIgoJRkvkkjpS
UxC1Caq7W7dngi2tdDVV7V14LAK428XxjscsQLGRbzvNXHRbu9Ck4Y2VWxir5pMF
Obht2q34sd5wTpsnjDvOzHgpAoGAbjm1h2fDcwO4L+4bydjx33OTzbzDzcPf8mJf
EnQ1AAcDUHYL1GE/XkSY3SOIwp0IKakXcKhMGxU96uW3Ht3MEuWwoqE5SxW3KRBL
1GD0WRXUJC0d+jOEPEwycL9GQ5jmobDYzYUhfK1Cod3lr4WoWG2rwm37VA09RPRq
u1rQ53kCgYEA8sgMEh37IZ4XzS30HC4eBunmruH8Tt753eIdxSbnxUtw/F5ihTXi
AC7KYntlsuhhv0HRYURLUXP79KDtjdOv8pONyoPAmj8lkmDP5k0Fue7yoy072BRb
12NS0Y7sBbI/BvDp8DMEVLApa62ZWPIacfgtn82mFX84av2SMLgvFd0=
-----END RSA PRIVATE KEY-----
`
	publicPem := `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5/RxR0Gk6jKrvmGmOmEO
G/AThlv4wUjosZXmHxaJgfpYyoSq/VP+eXnSigrXmYLVJBknbQglk0Z+uku5n9QM
Ki+Ih6NQAkXxkE0xGb8CWuC6vGfYrkBmi8/UTqeberGx1he1RYw90PpSg4V2n2Sa
mZqfTcr0cV6lB5FSSzXBmTuSG9oDjmxTg2yw933DB6OiJOZhHBroIsutG5tR0zfA
YgLD4CR9l1GtDweWelm0pdinhtSG0xnUtH7dRE4KjE64TgUm6ajpH/+satnrJDHU
Y4fpOACBBhK+i9fKKVIn1KSZ17zsd0LTrZhNKIKtoA+bVyOi4rT/9Bx/VUHeSkcv
uwIDAQAB
-----END PUBLIC KEY-----
`
	u := &User{"TangXiaodong", 100, "0000123","FUCK","Fkdas"}
	sig ,err :=StructSigningWithPem(u,privatekey)
	if err != nil {
		t.Fatal(err)
	}
	u.Signature=sig
	if err := StructSigningVerifyWithPem(u,publicPem,u.Signature);err != nil {
		t.Fatal(err)
	}
	t.Log("success")
}