package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

const TAG_LENGTH_BYTES = 16

func AesgcmDecrypt(key, nonce, data, mac []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCMWithTagSize(block, TAG_LENGTH_BYTES)
	if err != nil {
		return nil, err
	}
	ciphertext := append(data, mac...)

	return aesgcm.Open(nil, nonce, ciphertext, nil)
}
