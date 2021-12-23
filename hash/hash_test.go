package hash

import (
	"fmt"
	"testing"
)

func TestSha256(t *testing.T) {
	test_s := "hello world\n"
	hashres:=Sha256([]byte(test_s))
	fmt.Printf("%x",hashres)
}
