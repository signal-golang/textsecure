package registration

// RegistrationInfo holds the data required to be identified by and
// to communicate with the push server.
// The data is generated once at install time and stored locally.
/**
 * Verify a Signal Service account with a received SMS or voice verification code.
 *
 * @param verificationCode The verification code received via SMS or Voice
 *                         (see {@link #requestSmsVerificationCode} and
 *                         {@link #requestVoiceVerificationCode}).
 * @param signalingKey 52 random bytes.  A 32 byte AES key and a 20 byte Hmac256 key,
 *                     concatenated.
 * @param signalProtocolRegistrationId A random 14-bit number that identifies this Signal install.
 *                                     This value should remain consistent across registrations for the
 *                                     same install, but probabilistically differ across registrations
 *                                     for separate installs.
 *
 * @throws IOException
 */
type RegistrationInfo struct {
	Password       string
	RegistrationID uint32
	SignalingKey   []byte
	CaptchaToken   string
}

var Registration RegistrationInfo
