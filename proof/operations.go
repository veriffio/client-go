package proof

import (
	"crypto/sha256"

	"golang.org/x/crypto/sha3"
)

// These constants define the hash functions which are recognized by the package
// and the strings that must be used to identify them. The functions are
// implemented as defined in FIPS 180-4 and FIPS-202.
const (
	SHA2_256 = "sha2_256"
	SHA3_512 = "sha3_512"
)

var operations = map[string]func([]byte) []byte{
	SHA2_256: opSha2_256,
	SHA3_512: opSha3_512,
}

func opSha2_256(in []byte) []byte {
	sum := sha256.Sum256(in)
	return sum[:]
}
func opSha3_512(in []byte) []byte {
	sum := sha3.Sum512(in)
	return sum[:]
}
