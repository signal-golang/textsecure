// Based on https://gist.github.com/nanu-c/f885b928b9e43a7167258dd70dc186d6 from nanu-c
//which is based on https://github.com/signalapp/libsignal-protocol-java/blob/master/java/src/main/java/org/whispersystems/libsignal/fingerprint/NumericFingerprintGenerator.java
package fingerprint

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"

	"fmt"
	"hash"
	"sort"

	log "github.com/sirupsen/logrus"

	"github.com/signal-golang/textsecure/axolotl"
)

const ITERATIONS int = 5200
const FINGERPRINT_VERSION int16 = 0

//https://github.com/signalapp/libsignal-protocol-java/blob/fde96d22004f32a391554e4991e4e1f0a14c2d50/java/src/main/java/org/whispersystems/libsignal/fingerprint/NumericFingerprintGenerator.java#L85
//returns: the fingerprint in blocks of five digits
func CreateFingerprint(version uint32, localStableIdentifier []byte, localIdentityKeys []axolotl.ECPublicKey, remoteStableIdentifier []byte, remoteIdentityKeys []axolotl.ECPublicKey) ([]string, []byte, error) {

	lFingerprint := getFingerprint(ITERATIONS, localStableIdentifier, localIdentityKeys)
	rFingerprint := getFingerprint(ITERATIONS, remoteStableIdentifier, remoteIdentityKeys)

	fingerprintNumbers := CreateFingerprintNumbers(lFingerprint, rFingerprint)
	qrFingerprint, err := CreateQRFingerprint(version, lFingerprint, rFingerprint)
	if err != nil {
		return nil, nil, err
	}
	return fingerprintNumbers, qrFingerprint, nil
}

//I'm not particular happy with the name "CreateFingerprintSimple"
func CreateFingerprintSimple(version uint32, local string, localKey []byte, remote string, remoteKey []byte) ([]string, []byte, error) {

	localStableIdentifier, localECKeys := castParameters(local, localKey)

	remoteStableIdentifier, remoteECKeys := castParameters(remote, remoteKey)

	return CreateFingerprint(version, localStableIdentifier, localECKeys, remoteStableIdentifier, remoteECKeys)
}

func castParameters(identifier string, key []byte) ([]byte, []axolotl.ECPublicKey) {
	ECKey := *axolotl.NewECPublicKey(key[1:])
	ECKeys := []axolotl.ECPublicKey{ECKey}
	return []byte(identifier), ECKeys
}

//https://github.com/signalapp/libsignal-protocol-java/blob/master/java/src/main/java/org/whispersystems/libsignal/fingerprint/NumericFingerprintGenerator.java#L104
func getFingerprint(iterations int, stableIdentifier []byte, identityKeys []axolotl.ECPublicKey) []byte {
	publicKey := getLogicalKeyBytes(identityKeys)
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, FINGERPRINT_VERSION)
	if err != nil {
		fmt.Println("[textsecure] binary.Write failed:", err)
	}
	version := buf.Bytes()
	startData := append(version, publicKey...)
	startData = append(startData, stableIdentifier...)

	return repeatedHashing(startData, publicKey, iterations)
}

func repeatedHashing(startData []byte, key []byte, iterations int) []byte {
	digest := sha512.New()
	hash := startData
	for i := 0; i < iterations; i++ {
		javaLikeUpdate(digest, hash)
		hash = javaLikeDigest(digest, key)
	}

	return hash
}

//Based on Java MessageDigest
//update(input):
//"Updates the digest using the specified array of bytes."
func javaLikeUpdate(digest hash.Hash, data []byte) {
	digest.Write(data)
}

//Based on Java MessageDigest
//digest(input):
//"Performs a final update on the digest using the specified array of bytes,
//then completes the digest computation.
//That is, this method first calls update(input),
//passing the input array to the update method, then calls digest()."
//digest():
//"Completes the hash computation by performing final operations such as padding.
//The digest is reset after this call is made."
func javaLikeDigest(digest hash.Hash, data []byte) []byte {
	digest.Write(data)
	result := digest.Sum(nil)
	digest.Reset()
	return result
}

//https://github.com/signalapp/libsignal-protocol-java/blob/3662b6d705ae4162ad8b3a242daf35171edbb068/java/src/main/java/org/whispersystems/libsignal/fingerprint/NumericFingerprintGenerator.java#L122
func getLogicalKeyBytes(identityKeys []axolotl.ECPublicKey) []byte {
	// sort IdentityKeyComparator
	sorted := sortByteArrays(identityKeys)
	sort.Sort(sorted)
	var output []byte
	for k := range sorted {
		output = append(output, sorted[k].Serialize()...)
	}
	return output
}

// implement `Interface` in sort package.
type sortByteArrays []axolotl.ECPublicKey

func (b sortByteArrays) Len() int {
	return len(b)
}

func (b sortByteArrays) Less(i, j int) bool {
	// bytes package already implements Comparable for []byte.
	switch bytes.Compare(b[i].Serialize(), b[j].Serialize()) {
	case -1:
		return true
	case 0, 1:
		return false
	default:
		log.Panic("not fail-able with `bytes.Comparable` bounded [-1, 1].")
		return false
	}
}

func (b sortByteArrays) Swap(i, j int) {
	b[j], b[i] = b[i], b[j]
}

// Public
func SortByteArrays(src []axolotl.ECPublicKey) []axolotl.ECPublicKey {
	sorted := sortByteArrays(src)
	sort.Sort(sorted)
	return sorted
}
