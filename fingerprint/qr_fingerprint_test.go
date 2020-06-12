package fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	log "github.com/sirupsen/logrus"
)

const ALICE_TEL_QR = "+14152222222"

//https://github.com/signalapp/libsignal-protocol-java/blob/fde96d22004f32a391554e4991e4e1f0a14c2d50/tests/src/test/java/org/whispersystems/libsignal/fingerprint/NumericFingerprintGeneratorTest.java#L13
// Without first byte (0x05), since this implementation doesn't use a DJB_TYPE
var ALICE_KEY_QR = []byte{0x05, 0x06, 0x86, 0x3b, 0xc6, 0x6d, 0x02, 0xb4, 0x0d, 0x27,
	0xb8, 0xd4, 0x9c, 0xa7, 0xc0, 0x9e, 0x92, 0x39, 0x23, 0x6f, 0x9d, 0x7d,
	0x25, 0xd6, 0xfc, 0xca, 0x5c, 0xe1, 0x3c, 0x70, 0x64, 0xd8, 0x68}

const BOB_TEL_QR = "+14153333333"

//https://github.com/signalapp/libsignal-protocol-java/blob/fde96d22004f32a391554e4991e4e1f0a14c2d50/tests/src/test/java/org/whispersystems/libsignal/fingerprint/NumericFingerprintGeneratorTest.java#L14
// Without first byte (0x05), since this implementation doesn't use a DJB_TYPE
var BOB_KEY_QR = []byte{0x05, 0xf7, 0x81, 0xb6, 0xfb, 0x32, 0xfe, 0xd9, 0xba, 0x1c, 0xf2,
	0xde, 0x97, 0x8d, 0x4d, 0x5d, 0xa2, 0x8d, 0xc3, 0x40, 0x46, 0xae, 0x81,
	0x44, 0x02, 0xb5, 0xc0, 0xdb, 0xd9, 0x6f, 0xda, 0x90, 0x7b}

func TestCreateAndScanQRFingerprint(t *testing.T) {
	log.Debugln("test")
	var version uint32 = 1

	localStableIdentifier, localECKeys := castParameters(ALICE_TEL_QR, ALICE_KEY_QR)

	remoteStableIdentifier, remoteECKeys := castParameters(BOB_TEL_QR, BOB_KEY_QR)

	lFingerprint := getFingerprint(5200, localStableIdentifier, localECKeys)
	rFingerprint := getFingerprint(5200, remoteStableIdentifier, remoteECKeys)

	qrFingerprint, err := CreateQRFingerprint(version, lFingerprint, rFingerprint)
	assert.Nil(t, err)

	combinedFingerprints, err2 := ScanQRFingerprint(qrFingerprint)
	assert.Nil(t, err2)

	assert.Equal(t, *combinedFingerprints.Version, version)
	assert.Equal(t, combinedFingerprints.LocalFingerprint.Content, lFingerprint)
	assert.Equal(t, combinedFingerprints.RemoteFingerprint.Content, rFingerprint)

}
