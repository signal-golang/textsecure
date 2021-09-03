// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

// Package textsecure implements the TextSecure client protocol.
package textsecure

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"bytes"

	"github.com/signal-golang/mimemagic"

	"github.com/golang/protobuf/proto"

	"github.com/signal-golang/textsecure/axolotl"
	"github.com/signal-golang/textsecure/config"
	"github.com/signal-golang/textsecure/contacts"
	"github.com/signal-golang/textsecure/helpers"
	"github.com/signal-golang/textsecure/profiles"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	rootCa "github.com/signal-golang/textsecure/rootCa"
	"github.com/signal-golang/textsecure/transport"
	"github.com/signal-golang/textsecure/unidentifiedAccess"
	log "github.com/sirupsen/logrus"
)

// Generate a random 16 byte string used for HTTP Basic Authentication to the server
func generatePassword() string {
	b := make([]byte, 16)
	randBytes(b[:])
	return helpers.Base64EncWithoutPadding(b)
}

// Generate a random 14 bit integer
func generateRegistrationID() uint32 {
	return randUint32() & 0x3fff
}

// Generate a 256 bit AES and a 160 bit HMAC-SHA1 key
// to be used to secure the communication with the server
func generateSignalingKey() []byte {
	b := make([]byte, 52)
	randBytes(b[:])
	return b
}

func encodeKey(key []byte) string {
	return helpers.Base64EncWithoutPadding(append([]byte{5}, key[:]...))
}

// ErrBadPublicKey is raised when a given public key is not in the
// expected format.
var ErrBadPublicKey = errors.New("public key not formatted correctly")

func decodeKey(s string) ([]byte, error) {
	b, err := helpers.Base64DecodeNonPadded(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 33 || b[0] != 5 {
		return nil, ErrBadPublicKey
	}
	return b[1:], nil
}

func decodeSignature(s string) ([]byte, error) {
	b, err := helpers.Base64DecodeNonPadded(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 64 {
		return nil, fmt.Errorf("signature is %d, not 64 bytes", len(b))
	}
	return b, nil
}

func needsRegistration() bool {
	return !textSecureStore.valid()
}

var identityKey *axolotl.IdentityKeyPair

type att struct {
	id        uint64
	ct        string
	keys      []byte
	digest    []byte
	size      uint32
	voiceNote bool
}

type outgoingMessage struct {
	destination string
	msg         string
	group       *groupMessage
	groupV2     *signalservice.GroupContextV2
	attachment  *att
	flags       uint32
	expireTimer uint32
	timestamp   *uint64
}

// LinkedDevices returns the list of linked devices
func LinkedDevices() ([]DeviceInfo, error) {
	return getLinkedDevices()
}

// UnlinkDevice removes a linked device
func UnlinkDevice(id int) error {
	return unlinkDevice(id)
}

// NewDeviceVerificationCode returns the verification code for linking devices
func NewDeviceVerificationCode() (string, error) {
	return getNewDeviceVerificationCode()
}

// AddDevice links a new device
func AddDevice(ephemeralID, publicKey, verificationCode string) error {
	return addNewDevice(ephemeralID, publicKey, verificationCode)
}

// SendMessage sends the given text message to the given contact.
func SendMessage(uuid, msg string, timer uint32) (uint64, error) {
	omsg := &outgoingMessage{
		destination: uuid,
		msg:         msg,
		expireTimer: timer,
	}
	return sendMessage(omsg)
}

// MIMETypeFromReader returns the mime type that is inside the reader
func MIMETypeFromReader(r io.Reader) (mime string, reader io.Reader) {
	var buf bytes.Buffer
	io.CopyN(&buf, r, 1024)
	mime = mimemagic.Match("", buf.Bytes())
	return mime, io.MultiReader(&buf, r)
}

// SendAttachment sends the contents of a reader, along
// with an optional message to a given contact.
func SendAttachment(uuid string, msg string, r io.Reader, timer uint32) (uint64, error) {
	ct, r := MIMETypeFromReader(r)
	a, err := uploadAttachment(r, ct)
	if err != nil {
		return 0, err
	}
	omsg := &outgoingMessage{
		destination: uuid,
		msg:         msg,
		attachment:  a,
		expireTimer: timer,
	}
	return sendMessage(omsg)
}

// SendVoiceNote sends a voice note
func SendVoiceNote(uuid, msg string, r io.Reader, timer uint32) (uint64, error) {
	ct, r := MIMETypeFromReader(r)
	a, err := uploadVoiceNote(r, ct)
	if err != nil {
		return 0, err
	}
	omsg := &outgoingMessage{
		destination: uuid,
		msg:         msg,
		attachment:  a,
		expireTimer: timer,
	}
	return sendMessage(omsg)
}

// EndSession terminates the session with the given peer.
func EndSession(uuid string, msg string) (uint64, error) {
	omsg := &outgoingMessage{
		destination: uuid,
		msg:         msg,
		flags:       uint32(signalservice.DataMessage_END_SESSION),
	}
	ts, err := sendMessage(omsg)
	if err != nil {
		return 0, err
	}
	textSecureStore.DeleteAllSessions(recID(uuid))
	return ts, nil
}

// Attachment represents an attachment received from a peer
type Attachment struct {
	R        io.Reader
	MimeType string
	FileName string
}

// Client contains application specific data and callbacks.
type Client struct {
	GetPhoneNumber        func() string
	GetVerificationCode   func() string
	GetPin                func() string
	GetStoragePassword    func() string
	GetCaptchaToken       func() string
	GetConfig             func() (*config.Config, error)
	GetLocalContacts      func() ([]contacts.Contact, error)
	MessageHandler        func(*Message)
	TypingMessageHandler  func(*Message)
	ReceiptMessageHandler func(*Message)
	CallMessageHandler    func(*Message)
	ReceiptHandler        func(string, uint32, uint64)
	SyncReadHandler       func(string, uint64)
	SyncSentHandler       func(*Message, uint64)
	RegistrationDone      func()
	GetUsername           func() string
}

var (
	client *Client
)

// setupLogging sets the logging verbosity level based on configuration
// and environment variables
func setupLogging() {
	loglevel := config.ConfigFile.LogLevel
	if loglevel == "" {
		loglevel = os.Getenv("TEXTSECURE_LOGLEVEL")
	}

	switch strings.ToUpper(loglevel) {
	case "DEBUG":
		log.SetLevel(log.DebugLevel)
	case "INFO":
		log.SetLevel(log.InfoLevel)
	case "WARN":
		log.SetLevel(log.WarnLevel)
	case "ERROR":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.ErrorLevel)
	}

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006/01/02 15:04:05",
	})
}

// Setup initializes the package.
func Setup(c *Client) error {
	var err error
	client = c

	config.ConfigFile, err = loadConfig()
	if err != nil {
		return err
	}

	setupLogging()
	err = setupStore()
	if err != nil {
		return err
	}

	if needsRegistration() {
		registrationInfo.registrationID = generateRegistrationID()
		textSecureStore.SetLocalRegistrationID(registrationInfo.registrationID)

		registrationInfo.password = generatePassword()
		textSecureStore.storeHTTPPassword(registrationInfo.password)

		registrationInfo.signalingKey = generateSignalingKey()
		textSecureStore.storeHTTPSignalingKey(registrationInfo.signalingKey)

		identityKey = axolotl.GenerateIdentityKeyPair()
		err := textSecureStore.SetIdentityKeyPair(identityKey)
		if err != nil {
			return err
		}

		err = registerDevice()
		if err != nil {
			return err
		}
	}
	registrationInfo.registrationID, err = textSecureStore.GetLocalRegistrationID()
	if err != nil {
		return err
	}
	registrationInfo.password, err = textSecureStore.loadHTTPPassword()
	if err != nil {
		return err
	}
	registrationInfo.signalingKey, err = textSecureStore.loadHTTPSignalingKey()
	if err != nil {
		return err
	}

	client.RegistrationDone()
	rootCa.SetupCA(config.ConfigFile.RootCA)
	transport.SetupTransporter(config.ConfigFile.Server, config.ConfigFile.Tel, registrationInfo.password, config.ConfigFile.UserAgent, config.ConfigFile.ProxyServer)
	transport.SetupCDNTransporter(SIGNAL_CDN_URL, config.ConfigFile.Tel, registrationInfo.password, config.ConfigFile.UserAgent, config.ConfigFile.ProxyServer)
	transport.SetupDirectoryTransporter(DIRECTORY_URL, config.ConfigFile.Tel, registrationInfo.password, config.ConfigFile.UserAgent, config.ConfigFile.ProxyServer)
	transport.SetupStorageTransporter(STORAGE_URL, config.ConfigFile.Tel, registrationInfo.password, config.ConfigFile.UserAgent, config.ConfigFile.ProxyServer)
	identityKey, err = textSecureStore.GetIdentityKeyPair()
	// check if we have a uuid and if not get it
	config.ConfigFile = checkUUID(config.ConfigFile)
	profileChanged := false
	// check for a profileKey
	if len(config.ConfigFile.ProfileKey) == 0 {
		config.ConfigFile.ProfileKey = profiles.GenerateProfileKey()
		saveConfig(config.ConfigFile)
		profileChanged = true
	}
	// check if a username is set
	if config.ConfigFile.Name == "" {
		config.ConfigFile.Name = client.GetUsername()
		saveConfig(config.ConfigFile)
	}
	if profileChanged {
		profiles.UpdateProfile(config.ConfigFile.ProfileKey, config.ConfigFile.UUID, config.ConfigFile.Name)
	}

	// check for unidentified access
	if len(config.ConfigFile.Certificate) == 0 {
		err = renewSenderCertificate()
		if err != nil {
			return err
		}
	} else {
		err := unidentifiedAccess.CheckCertificate(config.ConfigFile.Certificate)
		if err != nil {
			err = renewSenderCertificate()
			if err != nil {
				return err
			}
		}
	}
	return err
}
func renewSenderCertificate() error {
	log.Infoln("Get new uidentified sender certificate")
	cert, err := transport.GetSenderCertificate()
	if err != nil {
		return err
	}
	config.ConfigFile.Certificate = cert.Certificate
	saveConfig(config.ConfigFile)
	log.Debug(fmt.Sprintf("[textsecure] Sender certificate: %s", cert))
	return nil

}

func registerDevice() error {
	if config.ConfigFile.Tel == "" {
		config.ConfigFile.Tel = client.GetPhoneNumber()
		if config.ConfigFile.Tel == "" {
			return errors.New("empty phone number")
		}
	}
	rootCa.SetupCA(config.ConfigFile.RootCA)
	transport.SetupTransporter(config.ConfigFile.Server, config.ConfigFile.Tel, registrationInfo.password, config.ConfigFile.UserAgent, config.ConfigFile.ProxyServer)
	// try to register without token
	code, responseCode, err := requestCode(config.ConfigFile.Tel, config.ConfigFile.VerificationType, "")
	if responseCode != nil {
		if *responseCode == responseNeedCaptcha {
			// Need to generate a token on https://signalcaptchas.org/registration/generate.html
			log.Infoln("[textsecure] registration needs captcha")

			captcha := client.GetCaptchaToken()
			code, _, err = requestCode(config.ConfigFile.Tel, config.ConfigFile.VerificationType, captcha)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	} else if err != nil {
		return err
	}
	if config.ConfigFile.VerificationType != "dev" {
		code = client.GetVerificationCode()
	}
	err, credentials := verifyCode(code, nil, nil)
	if err != nil {
		if credentials != nil {
			log.Warnln("[textsecure] verfication failed, try again with pin", err.Error())
			pin := client.GetPin()
			err, credentials = verifyCode(code, &pin, credentials)
			if err != nil {
				log.Warnln("[textsecure] verfication failed", err.Error())
				return err
			}
		} else {
			log.Warnln("[textsecure] verfication failed", err.Error())
			return err
		}

	}

	err = generatePreKeys()
	if err != nil {
		return err
	}
	err = generatePreKeyState()
	if err != nil {
		return err
	}
	err = registerPreKeys()
	if err != nil {
		return err
	}
	config.ConfigFile.ProfileKey = profiles.GenerateProfileKey()
	config.ConfigFile = checkUUID(config.ConfigFile)
	client.RegistrationDone()
	if client.RegistrationDone != nil {
		log.Infoln("[textsecure] RegistrationDone")

		client.RegistrationDone()
	}
	return nil
}

func handleReceipt(env *signalservice.Envelope) {
	if client.ReceiptHandler != nil {
		client.ReceiptHandler(env.GetSourceUuid(), env.GetSourceDevice(), env.GetTimestamp())
	}
}

// recID removes the + from phone numbers
func recID(source string) string {
	if source[0] == '+' {
		return source[1:]
	}
	return source
}

// EndSessionFlag signals that this message resets the session
var EndSessionFlag uint32 = 1

// ProfileKeyUpdatedFlag signals that this message updates the profile key
var ProfileKeyUpdatedFlag = signalservice.DataMessage_PROFILE_KEY_UPDATE

func handleFlags(src string, dm *signalservice.DataMessage) (uint32, error) {
	flags := uint32(0)
	if dm.GetFlags() == uint32(signalservice.DataMessage_END_SESSION) {
		flags = EndSessionFlag

		textSecureStore.DeleteAllSessions(recID(src))
		textSecureStore.DeleteAllSessions(src)
	}
	if dm.GetFlags() == uint32(signalservice.DataMessage_PROFILE_KEY_UPDATE) {
		err := contacts.UpdateProfileKey(src, dm.GetProfileKey())
		if err != nil {
			return 0, err
		}
		flags = uint32(signalservice.DataMessage_PROFILE_KEY_UPDATE)
	}
	return flags, nil
}

// MessageTypeNotImplementedError is raised in the unlikely event that an unhandled protocol message type is received.
type MessageTypeNotImplementedError struct {
	typ uint32
}

func (err MessageTypeNotImplementedError) Error() string {
	return fmt.Sprintf("not implemented message type %d", err.typ)
}

// ErrInvalidMACForMessage signals an incoming message with invalid MAC.
var ErrInvalidMACForMessage = errors.New("invalid MAC for incoming message")

// Authenticate and decrypt a received message
func handleReceivedMessage(msg []byte) error {
	// decrypt signalservice envelope
	macpos := len(msg) - 10
	tmac := msg[macpos:]
	aesKey := registrationInfo.signalingKey[:32]
	macKey := registrationInfo.signalingKey[32:]
	hasError := false
	if !axolotl.ValidTruncMAC(msg[:macpos], tmac, macKey) {
		hasError = true
		//return ErrInvalidMACForMessage
	}
	plaintext := []byte{}
	var err error
	// check if the message is using the signaling key
	if hasError {
		plaintext = msg
	} else {
		ciphertext := msg[1:macpos]
		plaintext, err = axolotl.Decrypt(aesKey, ciphertext)
		if err != nil {
			return err
		}
	}

	env := &signalservice.Envelope{}
	err = proto.Unmarshal(plaintext, env)
	if err != nil {
		return err
	}
	recid := env.GetSourceUuid()

	sc := axolotl.NewSessionCipher(textSecureStore, textSecureStore, textSecureStore, textSecureStore, recid, env.GetSourceDevice())
	switch *env.Type {
	case signalservice.Envelope_RECEIPT:
		handleReceipt(env)
		return nil
	case signalservice.Envelope_CIPHERTEXT:
		msg := env.GetContent()
		if msg == nil {
			return errors.New("[textsecure] Legacy messages unsupported")
		}
		wm, err := axolotl.LoadWhisperMessage(msg)
		if err != nil {
			log.Infof("[textsecure] Incoming WhisperMessage %s.\n", err)
			return err
		}
		b, err := sc.SessionDecryptWhisperMessage(wm)
		if _, ok := err.(axolotl.DuplicateMessageError); ok {
			log.Infof("[textsecure] Incoming WhisperMessage %s. Ignoring.\n", err)
			return nil
		}
		if _, ok := err.(axolotl.InvalidMessageError); ok {
			// try the legacy way
			log.Infof("[textsecure] Incoming WhisperMessage try legacy decrypting")

			recid := recID(env.GetSourceE164())
			sc := axolotl.NewSessionCipher(textSecureStore, textSecureStore, textSecureStore, textSecureStore, recid, env.GetSourceDevice())
			b, err = sc.SessionDecryptWhisperMessage(wm)
			if _, ok := err.(axolotl.DuplicateMessageError); ok {
				log.Infof("[textsecure] Incoming WhisperMessage %s. Ignoring.\n", err)
				return nil
			}
		}
		if err != nil {
			return err
		}
		err = handleMessage(env.GetSourceE164(), env.GetSourceUuid(), env.GetTimestamp(), b)
		if err != nil {
			return err
		}

	case signalservice.Envelope_PREKEY_BUNDLE:
		msg := env.GetContent()
		pkwm, err := axolotl.LoadPreKeyWhisperMessage(msg)
		if err != nil {
			return err
		}
		b, err := sc.SessionDecryptPreKeyWhisperMessage(pkwm)
		if _, ok := err.(axolotl.DuplicateMessageError); ok {
			log.Infof("[textsecure] Incoming PreKeyWhisperMessage %s. Ignoring.\n", err)
			return nil
		}
		if _, ok := err.(axolotl.PreKeyNotFoundError); ok {
			log.Infof("[textsecure] Incoming PreKeyWhisperMessage %s. Ignoring.\n", err)
			return nil
		}
		if _, ok := err.(axolotl.InvalidMessageError); ok {
			log.Infof("[textsecure] Incoming PreKeyWhisperMessage %s. Ignoring.\n", err)
			return nil
		}
		if err != nil {
			return err
		}
		err = handleMessage(env.GetSourceE164(), env.GetSourceUuid(), env.GetTimestamp(), b)
		if err != nil {
			return err
		}
	case signalservice.Envelope_UNIDENTIFIED_SENDER:

		msg := env.GetContent()
		str := string(msg)

		fmt.Println(str) // uint64 in string format

		return fmt.Errorf("not implemented message type unindentified sender %v", msg)

	default:
		return MessageTypeNotImplementedError{uint32(*env.Type)}
	}

	return nil
}
