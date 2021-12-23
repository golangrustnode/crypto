package rsa


import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

func SignWithRsa2(privateKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	hashed := sha256.Sum256(message)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
}

func VerifyWithRsa2(pub *rsa.PublicKey, message []byte, signature string) error {
	hashed := sha256.Sum256(message)
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sig)
}

func GeneraRsa2Key() (*rsa.PrivateKey, error) {
	bitSize := 2048
	return rsa.GenerateKey(rand.Reader, bitSize)
}

func KeyToPem(privateKey *rsa.PrivateKey) ([]byte, []byte, error) {
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privPem := pem.EncodeToMemory(privBlock)
	publicKey := &privateKey.PublicKey
	publicBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	}
	pubPem := pem.EncodeToMemory(pubBlock)
	return privPem, pubPem, nil
}

func GetPubKeyFromPem(pubPem []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubPem)
	pubByte := block.Bytes
	pub, err := x509.ParsePKIXPublicKey(pubByte)
	if err != nil {
		return nil, err
	}
	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to 转换成公钥")
	}
	return publicKey, nil
}

func GetPrivKeyFromPem(priPem []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priPem)
	privByte := block.Bytes
	return x509.ParsePKCS1PrivateKey(privByte)
}

