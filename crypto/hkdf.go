package crypto

import (
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

func HKDFderiveSecrets(inputKeyMaterial, info []byte, outputLength int) ([]byte, error) {
	salt := make([]byte, 32)
	prekey := hkdf.Extract(sha256.New, inputKeyMaterial, salt)
	reader := hkdf.Expand(sha256.New, prekey, info)
	secret := make([]byte, outputLength)
	read, err := reader.Read(secret)
	if err != nil {
		return nil, err
	}
	if read != outputLength {
		//error?
	}
	return secret, nil
}
