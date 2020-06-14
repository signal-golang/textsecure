package fingerprint

import (
	proto "github.com/golang/protobuf/proto"
	"github.com/signal-golang/textsecure/axolotl/protobuf"
	"golang.org/x/text/encoding/charmap"
)
//based on https://github.com/signalapp/libsignal-protocol-java/blob/3662b6d705ae4162ad8b3a242daf35171edbb068/java/src/main/java/org/whispersystems/libsignal/fingerprint/ScannableFingerprint.java
//and https://github.com/signalapp/Signal-Android/blob/6f39f9849a002f6361d192a00fbd7c52ffaf3bba/app/src/main/java/org/thoughtcrime/securesms/VerifyIdentityActivity.java#
func CreateQRFingerprint(version uint32, localFingerprint []byte, remoteFingerprint []byte) (string, error) {
	combinedFingerprints := &textsecure.CombinedFingerprints{
		Version: &version,
		LocalFingerprint: &textsecure.LogicalFingerprint{
			Content: localFingerprint[:32],
		},
		RemoteFingerprint: &textsecure.LogicalFingerprint{
			Content: remoteFingerprint[:32],
		},
	}
    //https://github.com/signalapp/libsignal-protocol-java/blob/3662b6d705ae4162ad8b3a242daf35171edbb068/java/src/main/java/org/whispersystems/libsignal/fingerprint/ScannableFingerprint.java#L43
	data, err := proto.Marshal(combinedFingerprints)
	if err != nil {
		return "", err
	}
    //https://github.com/signalapp/Signal-Android/blob/6f39f9849a002f6361d192a00fbd7c52ffaf3bba/app/src/main/java/org/thoughtcrime/securesms/VerifyIdentityActivity.java#L501
	decoder := charmap.ISO8859_1.NewDecoder()
	var qrCodeContent []byte
	qrCodeContent, err = decoder.Bytes(data)
	if err != nil {
		return "", err
	}
	return string(qrCodeContent), nil
}

//based on https://github.com/signalapp/Signal-Android/blob/6f39f9849a002f6361d192a00fbd7c52ffaf3bba/app/src/main/java/org/thoughtcrime/securesms/VerifyIdentityActivity.java#L403
//and https://github.com/signalapp/libsignal-protocol-java/blob/3662b6d705ae4162ad8b3a242daf35171edbb068/java/src/main/java/org/whispersystems/libsignal/fingerprint/ScannableFingerprint.java#L54
func ScanQRFingerprint(qrCodeContent string) (*textsecure.CombinedFingerprints, error) {
	content := []byte(qrCodeContent)
	encoder := charmap.ISO8859_1.NewEncoder()
	data, err := encoder.Bytes(content)
	if err != nil {
		return nil, err
	}
	combinedFingerprints := &textsecure.CombinedFingerprints{}
	err = proto.Unmarshal(data, combinedFingerprints)
	if err != nil {
		return nil, err
	}
	return combinedFingerprints, nil
}
