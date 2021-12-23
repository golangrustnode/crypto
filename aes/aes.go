package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	log "github.com/sirupsen/logrus"
	"io"
)

func Encrypt(content string, aesPass []byte) (string, error)  {
	block, err := aes.NewCipher(aesPass)
	if err != nil {
		log.Error(err)
		return "", err
	}
	blocksize := block.BlockSize()
	rawData := PKCS7Padding([]byte(content), blocksize)

	cipherText := make([]byte, blocksize+len(rawData))
	iv := cipherText[:blocksize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Error(err)
		return "", nil
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[blocksize:], rawData)
	return hex.EncodeToString(cipherText), nil

}

func Decrypt(encryptedContent string, aesPass []byte) (string, error)  {
	block, err := aes.NewCipher(aesPass)
	if err != nil {
		log.Error(err)
		return "", err
	}
	encryptByte, err := hex.DecodeString(encryptedContent)
	if err != nil {
		log.Error(err)
		return "", err
	}
	blocksize := block.BlockSize()
	if len(encryptByte) < blocksize {
		return "", errors.New("cipher text is too short" + string(encryptByte))
	}
	if len(encryptByte)%blocksize != 0 {
		return "", errors.New("密文长度不是blocksize的整数倍")
	}
	iv := encryptByte[:blocksize]
	encryptData := encryptByte[blocksize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	decryptData := make([]byte, len(encryptData))
	mode.CryptBlocks(encryptData, encryptData)
	decryptData = PKCS7UnPadding(encryptData)
	return string(decryptData), nil
}
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}