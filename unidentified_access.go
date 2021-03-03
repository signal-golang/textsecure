package textsecure

import (
	"crypto/aes"
	"crypto/cipher"
)

func deriveAccessKeyFrom(profileKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(profileKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	input := make([]byte, 16)

	ciphertext := aesgcm.Seal(nil, nonce, input, nil)
	return ciphertext[:16], nil
}
