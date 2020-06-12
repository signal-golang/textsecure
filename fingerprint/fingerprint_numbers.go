package fingerprint

import (
	"fmt"
	"strings"
)

func CreateFingerprintNumbers(localFingerprint []byte, remoteFingerprint []byte) []string {
	local := getFingerprintNumbersFor(localFingerprint)
	remote := getFingerprintNumbersFor(remoteFingerprint)
	if compareFingerprintBlocks(local, remote) <= 0 {
		return append(local, remote...)
	}
	return append(remote, local...)
}

func compareFingerprintBlocks(localBlocks []string, remoteBlocks []string) int {
	result := len(localBlocks) - len(remoteBlocks)
	if result == 0 {
		result = strings.Compare(localBlocks[0], remoteBlocks[0])
		if result == 0 && len(localBlocks) > 0 {
			return compareFingerprintBlocks(localBlocks[1:], remoteBlocks[1:])
		}
	}
	return result
}

//https://github.com/signalapp/libsignal-protocol-javascript/blob/f5a838f1ccc9bddb5e93b899a63de2dea9670e10/src/NumericFingerprint.js#L32
func getFingerprintNumbersFor(fingerprint []byte) []string {
	chunks := []string{getEncodedChunk(fingerprint, 0),
		getEncodedChunk(fingerprint, 5),
		getEncodedChunk(fingerprint, 10),
		getEncodedChunk(fingerprint, 15),
		getEncodedChunk(fingerprint, 20),
		getEncodedChunk(fingerprint, 25)}
	return chunks
}

//https://github.com/signalapp/libsignal-protocol-javascript/blob/f5a838f1ccc9bddb5e93b899a63de2dea9670e10/src/NumericFingerprint.js#L19
func getEncodedChunk(hash []byte, offset int) string {
	chunk := byteArray5ToLong(hash, offset) % 100000
	return fmt.Sprintf("%05d", chunk)
}

//https://github.com/signalapp/libsignal-protocol-java/blob/4f5e1ff299cea22cc75bb97249020a7da67b816d/java/src/main/java/org/whispersystems/libsignal/util/ByteUtil.java#L225
func byteArray5ToLong(bytes []byte, offset int) uint64 {
	a := (uint64(bytes[offset]&0xff) << 32) |
		(uint64(bytes[offset+1]&0xff) << 24) |
		(uint64(bytes[offset+2]&0xff) << 16) |
		(uint64(bytes[offset+3]&0xff) << 8) |
		uint64(bytes[offset+4]&0xff)
	return a
}
