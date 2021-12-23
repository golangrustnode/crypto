package rsa

import (
	"encoding/hex"
	log "github.com/sirupsen/logrus"
	"testing"
)

func TestGeneraRsa2Key(t *testing.T) {
	privateKey, err := GeneraRsa2Key()
	if err != nil {
		log.Fatal(err)
	}
	log.Info(privateKey.D.String())
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
	err = VerifyWithRsa2(pub,msg,hex.EncodeToString(sig))
	log.Info(err)
}
