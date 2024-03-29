package sealedsessions

type SealedSessionCipher struct {
	LocalE164Address string
	LocalUuidAddress string
	LocalDeviceId    int
	Key              []byte
}
type UnidentifiedSenderMessageContent struct {
	handle []byte
}

func (s *SealedSessionCipher) Decrypt(data []byte) ([]byte, error) {

	// SignalProtocolAddress sender = new SignalProtocolAddress(message.getSenderCertificate().getSenderUuid(), message.getSenderCertificate().getSenderDeviceId());

	// switch (message.getType()) {
	//   case CiphertextMessage.WHISPER_TYPE:
	//     return new SessionCipher(signalProtocolStore, sender).decrypt(new SignalMessage(message.getContent()));
	//   case CiphertextMessage.PREKEY_TYPE:
	//     return new SessionCipher(signalProtocolStore, sender).decrypt(new PreKeySignalMessage(message.getContent()));
	//   case CiphertextMessage.SENDERKEY_TYPE:
	//     return new GroupCipher(signalProtocolStore, sender).decrypt(message.getContent());
	//   case CiphertextMessage.PLAINTEXT_CONTENT_TYPE:
	//     return Native.PlaintextContent_DeserializeAndGetContent(message.getContent());
	//   default:
	//     throw new InvalidMessageException("Unknown type: " + message.getType());
	// }
	return nil, nil
}
