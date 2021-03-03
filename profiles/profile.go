package profiles

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"

	zkgroup "github.com/nanu-c/zkgroup"
	uuidUtil "github.com/satori/go.uuid"
	"github.com/signal-golang/textsecure/crypto"
	"github.com/signal-golang/textsecure/transport"
)

const (
	PROFILE_PATH       = "/v1/profile/%s"
	NAME_PADDED_LENGTH = 53
)

// Profile ...
type Profile struct {
	Version    string `json:"version"`
	Name       []byte `json:"name"`
	Avatar     bool   `json:"avatar"`
	Commitment []byte `json:"commitment"`
}

// GenerateProfileKey generates a new ProfileKey
func GenerateProfileKey() []byte {
	profileKey := make([]byte, 32)
	rand.Read(profileKey)
	return profileKey
}
func uuidToByte(id string) []byte {
	s, _ := uuidUtil.FromString(id)
	return s.Bytes()
}

// UpdateProfile ...
func UpdateProfile(profileKey []byte, uuid, name string) error {
	uuidByte := uuidToByte(uuid)

	profile := Profile{}
	version, err := zkgroup.ProfileKeyGetProfileKeyVersion(profileKey, uuidByte)
	if err != nil {
		return err
	}
	commitment, err := zkgroup.ProfileKeyGetCommitment(profileKey, uuidByte)
	if err != nil {
		return err
	}
	nameCiphertext, err := encryptName(profileKey, []byte(name), NAME_PADDED_LENGTH)
	if err != nil {
		return err
	}
	profile.Version = string(version[:])
	profile.Commitment = commitment
	profile.Name = nameCiphertext
	profile.Avatar = false
	writeProfile(profile)
	if err != nil {
		return err
	}
	return nil
}

// WriteProfile ...
func writeProfile(profile Profile) error {
	// String response = makeServiceRequest(String.format(PROFILE_PATH, ""), "PUT", requestBody);
	body, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	transport.Transport.PutJSON(fmt.Sprintf(PROFILE_PATH, ""), body)
	return nil
}

func encryptName(key, input []byte, paddedLength int) ([]byte, error) {
	inputLength := len(input)
	if inputLength > paddedLength {
		return nil, errors.New("Input too long")
	}
	padded := append(input, make([]byte, paddedLength-inputLength)...)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	ciphertext, err := crypto.AesgcmEncrypt(key, nonce, padded)
	if err != nil {
		return nil, err
	}
	return append(nonce, ciphertext...), nil
}

func decryptName(key, nonceAndCiphertext []byte) ([]byte, error) {
	if len(nonceAndCiphertext) < 12+16+1 {
		return nil, errors.New("nonceAndCipher too short")
	}
	nonce := nonceAndCiphertext[:12]
	ciphertext := nonceAndCiphertext[12:]
	padded, err := crypto.AesgcmDecrypt(key, nonce, ciphertext, []byte{})
	if err != nil {
		return nil, err
	}
	paddedLength := len(padded)
	plaintextLength := 0
	for i := paddedLength - 1; i >= 0; i-- {
		if padded[i] != byte(0) {
			plaintextLength = i + 1
			break
		}
	}
	return padded[:plaintextLength], nil
}

func getCommitment(profileKey, uuid []byte) ([]byte, error) {
	return zkgroup.ProfileKeyGetCommitment(profileKey, uuid)
}
