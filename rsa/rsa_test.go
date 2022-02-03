package rsa

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	log "github.com/sirupsen/logrus"
	"reflect"
	"testing"
)

func TestGeneraRsa2Key(t *testing.T) {
	privateKey, err := GeneraRsa2Key()
	if err != nil {
		log.Fatal(err)
	}
	log.Info("private key length:",len(privateKey.D.String()))
	log.Info(len(privateKey.D.Bytes()))
	privPem, pubPem, err := KeyToPem(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Info(string(privPem))
	log.Info(string(pubPem))
	priv, err := GetPrivKeyFromPem(privPem)
	if err != nil {
		log.Fatal(err)
	}
	log.Info("priv:", priv.D.String())
	pub, err := GetPubKeyFromPem(pubPem)
	if err != nil {
		log.Fatal(err)
	}
	log.Info(pub.N.String())
	msg := []byte("hello world")
	sig,_ := SignWithRsa2(priv,msg)
	log.Info(hex.EncodeToString(sig))
	fmt.Println("sig base64 length:",len(base64.StdEncoding.EncodeToString(sig))," byte length",len(sig))
	err = VerifyWithRsa2(pub,msg,hex.EncodeToString(sig))
	log.Info(err)
}

func TestKeyToPem(t *testing.T) {
	type args struct {
		privateKey *rsa.PrivateKey
	}
	privateK,_:= GeneraRsa2Key()
	tests := []struct {
		name    string
		args    args
		want    []byte
		want1   []byte
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name:"test1",
			args: args{
				privateKey: privateK,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := KeyToPem(tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyToPem() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyToPem() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("KeyToPem() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestGetPubKeyFromPem(t *testing.T) {
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

	priv,err :=GetPrivKeyFromPem([]byte(privatekey))
	if err != nil {
		t.Fatal(err)
	}
	pub,err := GetPubKeyFromPem([]byte(publicPem))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello world")
	sig,_ := SignWithRsa2(priv,msg)
	log.Info(hex.EncodeToString(sig))
	fmt.Println("sig base64 length:",len(base64.StdEncoding.EncodeToString(sig))," byte length",len(sig))
	err = VerifyWithRsa2(pub,msg,hex.EncodeToString(sig))
	log.Info(err)

}