package hash

import (
	"fmt"
	"testing"
)

func TestHash_sha256(t *testing.T) {
	test_s := "hello world\n"
	hashres:=Hash_sha256([]byte(test_s))
	fmt.Printf("%x",hashres)
}
