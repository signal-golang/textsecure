package contactDiscoveryCrypto

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	addressBook        = []string{"4467060706060"}
	queryDataKey       = int8toByteArray(48, -93, 23, 89, 42, 38, 19, 106, 96, -33, 77, 36, -93, 68, 83, -83, -115, -60, -70, -76, -17, -69, 117, 100, -118, 31, 13, -96, -47, 17, -78, -66)
	queryData          = int8toByteArray(-96, 30, 112, 36, 118, -22, 126, -11, 20, 100, -107, -48, -94, 81, 71, -89, -1, 107, -49, 80, 16, 60, 64, 116, 78, -81, -1, 5, -41, -52, -67, -43, 0, 0, 4, 16, 17, -111, 11, 12)
	encryptedQueryData = AESEncryptedResult{
		iv:   int8toByteArray(-62, -125, 70, 88, 85, 58, -103, -6, -83, -87, -87, 0),
		data: int8toByteArray(-43, -52, 106, 13, -24, 64, 41, 110, -33, -5, -34, -69, 56, 44, 36, 82, -23, -100, -117, -100, 0, -38, 67, -128, -81, -53, -73, 104, -16, -12, -122, 101, 6, 116, -27, -106, -96, 37, -23, 6),
		mac:  int8toByteArray(103, 114, -107, -35, -107, 94, 78, 2, 115, -78, 123, 83, 4, -128, 54, -9),
		aad:  nil,
	}
	commitment = int8toByteArray(-103, 76, 43, -1, 94, -2, 51, 96, 24, -61, 18, -113, 65, 69, 50, -125, -86, -65, 83, -88, 106, -20, -106, 116, -126, 48, 122, -43, -29, 43, -30, 91)
	entry      = "bba07fc7-5d44-40fd-b63c-3909949f45ce"

	discoveryRequest = DiscoveryRequest{
		AddressCount: 1,
		Commitment:   fromBase64("mUwr/17+M2AYwxKPQUUyg6q/U6hq7JZ0gjB61eMr4ls="),
		Iv:           fromBase64("woNGWFU6mfqtqakA"),
		Data:         fromBase64("1cxqDehAKW7f+967OCwkUumci5wA2kOAr8u3aPD0hmUGdOWWoCXpBg=="),
		Mac:          fromBase64("Z3KV3ZVeTgJzsntTBIA29w=="),
		Envelopes: map[string]*QueryEnvelope{
			"bba07fc7-5d44-40fd-b63c-3909949f45ce": &QueryEnvelope{
				Data:      fromBase64("Wg53y3BtjkuxEmvCEByFUfiwReaszt4Wpa1gH0IpYew="),
				Iv:        fromBase64("VS+Ygv5XXvmZ5I6K"),
				Mac:       fromBase64("nl/bgPX1OdbVcBerOmhllA=="),
				RequestId: fromBase64("RuP9YiMUDc18omowRZk+ynHNAhdQiYMR/ELT5IWsHt0sPEaQ"),
			},
		},
	}
)

func int8toByteArray(in ...int8) []byte {
	out := make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		out[i] = int8toByte(in[i])
	}
	return out
}

func int8toByte(i int8) byte {
	return byte(i)
}

func Test0Int8toByte(t *testing.T) {
	result := int8toByte(-128)
	var b byte = 0x80
	assert.Equal(t, b, result)
}

func TestMinInt8toByte(t *testing.T) {
	result := int8toByte(0)
	var b byte
	assert.Equal(t, b, result)
}

func Test11Int8toByte(t *testing.T) {
	result := int8toByte(11)
	var b byte = 0x0b
	assert.Equal(t, b, result)
}

func Test12Int8toByte(t *testing.T) {
	result := int8toByte(12)
	var b byte = 0x0c
	assert.Equal(t, b, result)
}

func fromBase64(encoded string) []byte {
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	return decoded
}

func TestBuildQueryData(t *testing.T) {
	result, err := buildQueryDataWithNonce(addressBook, queryData[:32])
	assert.Nil(t, err)
	assert.Equal(t, queryData, result)
}

func TestAesEncryptNonce(t *testing.T) {
	result, err := aesEncryptNonce(queryDataKey, nil, queryData, encryptedQueryData.iv)
	assert.Nil(t, err)
	assert.Equal(t, &encryptedQueryData, result)
}

func TestCompareCommitment(t *testing.T) {
	assert.Equal(t, commitment, discoveryRequest.Commitment)
}

func TestHashSha256(t *testing.T) {
	result := hashSha256(queryData)
	assert.Equal(t, commitment, result)
}
