package hash

import "crypto/sha256"

func Sha256(data []byte) []byte {
	sum:=sha256.Sum256(data)
	return sum[:]
}
