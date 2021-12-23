package aes

import (
	"github.com/golangrustnode/crypto/hash"
	"testing"
)

func TestEncrypt(t *testing.T) {
	pass := hash.Sha256([]byte("dkfasdfsa"))
	str := "拉丁文 dfkalds|.lI。，"
	encstr, _ := Encrypt(str, pass[:])
	decstr, _ := Decrypt(encstr, pass[:])
	t.Log(string(decstr))
}

func TestDecrypt(t *testing.T) {

}