package contactDiscoveryCrypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"github.com/signal-golang/textsecure/contactsDiscovery"
)

type QueryEnvelope struct {
	Data      []byte `json:"data"`
	Iv        []byte `json:"iv"`
	Mac       []byte `json:"mac"`
	RequestId []byte `json:"requestId"`
}

type DiscoveryRequest struct {
	AddressCount int                       `json:"addressCount"`
	Commitment   []byte                    `json:"commitment"`
	Data         []byte                    `json:"data"`
	Envelopes    map[string]*QueryEnvelope `json:"envelopes"`
	Iv           []byte                    `json:"iv"`
	Mac          []byte                    `json:"mac"`
}

type RemoteAttestation struct {
	RequestId []byte
	Keys      RemoteAttestationKeys
	Cookies   []string
}
type RemoteAttestationKeys struct {
	ClientKey []byte
	ServerKey []byte
}

func CreateDiscoveryRequest(addressBook []string, remoteAttestations map[string]*contactsDiscovery.RemoteAttestation) (*DiscoveryRequest, error) {
	queryDataKey, err := getRandomBytes(32)
	if err != nil {
		return nil, err
	}
	queryData, err := buildQueryData(addressBook)
	if err != nil {
		return nil, err
	}
	encryptedQueryData, err := aesEncrypt(queryDataKey, nil, queryData)
	if err != nil {
		return nil, err
	}
	commitment := hashSha256(queryData)
	envelopes := make(map[string]*QueryEnvelope)
	for key, attestation := range remoteAttestations {
		envelopes[key], err = buildQueryEnvelopeFromAttestation(attestation, queryDataKey)
		if err != nil {
			return nil, err
		}
	}

	return &DiscoveryRequest{
		AddressCount: len(addressBook),
		Commitment:   commitment,
		Data:         encryptedQueryData.data,
		Envelopes:    envelopes,
		Iv:           encryptedQueryData.iv,
		Mac:          encryptedQueryData.mac}, nil
}

func getRandomBytes(length int) ([]byte, error) {
	random := make([]byte, length)
	_, err := rand.Read(random)
	if err != nil {
		return nil, err
	}
	return random, nil
}

func buildQueryData(addressBook []string) ([]byte, error) {
	nonce, err := getRandomBytes(32)
	if err != nil {
		return nil, err
	}
	return buildQueryDataWithNonce(addressBook, nonce)
}

func buildQueryDataWithNonce(addressBook []string, nonce []byte) ([]byte, error) {
	var addressData []byte
	for _, address := range addressBook {
		addressID, err := parse(address)
		if err != nil {
			return nil, err
		}
		addressData = append(addressData, toByteArray(addressID)...)
	}
	return append(nonce, addressData...), nil
}

func parse(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

func toByteArray(i int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(i))
	return b
}

func toLong(a []byte) int64 {
	return int64(binary.BigEndian.Uint64(a))
}

func buildQueryEnvelopeFromAttestation(attestation *contactsDiscovery.RemoteAttestation, queryDataKey []byte) (*QueryEnvelope, error) {
	return buildQueryEnvelope(attestation.RequestId, attestation.Keys.ClientKey, queryDataKey)
}

func buildQueryEnvelope(requestID, clientKey, queryDataKey []byte) (*QueryEnvelope, error) {
	result, err := aesEncrypt(clientKey, requestID, queryDataKey)
	if err != nil {
		return nil, err
	}
	return &QueryEnvelope{
		Data:      result.data,
		Mac:       result.mac,
		Iv:        result.iv,
		RequestId: requestID,
	}, nil
}

type AESEncryptedResult struct {
	iv,
	data,
	mac,
	aad []byte
}

func aesEncrypt(key, aad, data []byte) (*AESEncryptedResult, error) {
	nonce, err := getRandomBytes(12) //iv
	if err != nil {
		return nil, err
	}
	return aesEncryptNonce(key, aad, data, nonce)
}

const TAG_LENGTH_BYTES = 16

func aesEncryptNonce(key, aad, data, nonce []byte) (*AESEncryptedResult, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCMWithTagSize(block, TAG_LENGTH_BYTES)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, data, aad)
	macStart := len(ciphertext) - TAG_LENGTH_BYTES
	macPart := ciphertext[macStart:]
	dataPart := ciphertext[:macStart]
	return &AESEncryptedResult{nonce, dataPart, macPart, aad}, nil
}

func hashSha256(queryData []byte) []byte {
	hash := sha256.Sum256(queryData)
	return hash[:]
}

func GetDiscoveryResponseData(response DiscoveryResponse, remoteAttestations map[string]*contactsDiscovery.RemoteAttestation) ([]byte, error) {
	for _, attestation := range remoteAttestations {
		if bytes.Equal(response.RequestId, attestation.RequestId) {
			return aesDecrypt(attestation.Keys.ServerKey, response.Iv, response.Data, response.Mac, nil)
		}
	}

	return nil, errors.New("No matching RequestId")
}

type DiscoveryResponse struct {
	Data      []byte `json:"data"`
	Iv        []byte `json:"iv"`
	Mac       []byte `json:"mac"`
	RequestId []byte `json:"requestId"`
}

func aesDecrypt(key, nonce, data, mac, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCMWithTagSize(block, TAG_LENGTH_BYTES)
	if err != nil {
		return nil, err
	}
	ciphertext := append(data, mac...)
	return aesgcm.Open(nil, nonce, ciphertext, aad)
}
