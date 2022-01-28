// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

// Package textsecure implements the TextSecure client protocol.
package textsecure

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"bytes"

	"github.com/signal-golang/mimemagic"

	"github.com/golang/protobuf/proto"

	"github.com/signal-golang/textsecure/axolotl"
	"github.com/signal-golang/textsecure/config"
	"github.com/signal-golang/textsecure/contacts"
	crayfish "github.com/signal-golang/textsecure/crayfish"
	"github.com/signal-golang/textsecure/helpers"
	"github.com/signal-golang/textsecure/profiles"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	"github.com/signal-golang/textsecure/registration"
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
	//set signaling key version
	b[0] = 1
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
	uuidClean, err := recID(uuid)
	if err != nil {
		return 0, err
	}
	textSecureStore.DeleteAllSessions(uuidClean)
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
	go crayfish.Run()
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
		registration.Registration = registration.RegistrationInfo{
			RegistrationID: generateRegistrationID(),
		}
		textSecureStore.SetLocalRegistrationID(registration.Registration.RegistrationID)

		registration.Registration.Password = generatePassword()
		textSecureStore.storeHTTPPassword(registration.Registration.Password)

		registration.Registration.SignalingKey = generateSignalingKey()
		textSecureStore.storeHTTPSignalingKey(registration.Registration.SignalingKey)

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
	registration.Registration.RegistrationID, err = textSecureStore.GetLocalRegistrationID()
	if err != nil {
		return err
	}
	registration.Registration.Password, err = textSecureStore.loadHTTPPassword()
	if err != nil {
		return err
	}
	registration.Registration.SignalingKey, err = textSecureStore.loadHTTPSignalingKey()
	if err != nil {
		return err
	}

	client.RegistrationDone()
	rootCa.SetupCA(config.ConfigFile.RootCA)
	transport.SetupTransporter(config.ConfigFile.Server, config.ConfigFile.UUID, registration.Registration.Password, config.ConfigFile.UserAgent, config.ConfigFile.ProxyServer)
	transport.SetupCDNTransporter(SIGNAL_CDN_URL, config.ConfigFile.UUID, registration.Registration.Password, config.ConfigFile.UserAgent, config.ConfigFile.ProxyServer)
	transport.SetupDirectoryTransporter(DIRECTORY_URL, config.ConfigFile.UUID, registration.Registration.Password, config.ConfigFile.UserAgent, config.ConfigFile.ProxyServer)
	transport.SetupStorageTransporter(STORAGE_URL, config.ConfigFile.UUID, registration.Registration.Password, config.ConfigFile.UserAgent, config.ConfigFile.ProxyServer)
	identityKey, err = textSecureStore.GetIdentityKeyPair()
	// check if we have a uuid and if not get it
	// config.ConfigFile = checkUUID(config.ConfigFile)
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
		profileChanged = true
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
	if len(config.ConfigFile.ProfileKeyCredential) == 0 || true {
		profiles.UpdateProfile(config.ConfigFile.ProfileKey, config.ConfigFile.UUID, config.ConfigFile.Name)
		profile, err := profiles.GetProfileAndCredential(config.ConfigFile.UUID, config.ConfigFile.ProfileKey)
		if err != nil {
			return err
		}
		config.ConfigFile.ProfileKeyCredential = []byte(profile.Credential)
		saveConfig(config.ConfigFile)

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
func RegisterWithCrayfish(regisrationInfo *registration.RegistrationInfo, phoneNumber, captcha string) error {
	err := crayfish.Instance.CrayfishRegister(regisrationInfo, phoneNumber, captcha)
	if err != nil {
		return err
	}
	return nil

}

func registerDevice() error {
	log.Debugln("[texsecure] register Device")
	var err error
	config.ConfigFile, err = loadConfig()
	if err != nil {
		return err
	}
	rootCa.SetupCA(config.ConfigFile.RootCA)

	log.Debugln("[textsecure] Crayfish registration starting")
	client.GetConfig()
	phoneNumber := client.GetPhoneNumber()
	captcha := client.GetCaptchaToken()
	err = RegisterWithCrayfish(&registration.Registration, phoneNumber, captcha)
	if err != nil {
		log.Errorln("[textsecure] Crayfish registration failed", err)
		return err
	}
	code := client.GetVerificationCode()
	crayfishRegistration, err := crayfish.Instance.CrayfishRegisterWithCode(&registration.Registration, phoneNumber, captcha, code)
	if err != nil {
		log.Errorln("[textsecure] Crayfish registration failed", err)
		return err
	}
	config.ConfigFile.Tel = crayfishRegistration.Tel
	config.ConfigFile.UUID = crayfishRegistration.UUID
	config.ConfigFile.AccountCapabilities = config.AccountCapabilities{
		Gv2:               true,
		SenderKey:         false,
		AnnouncementGroup: false,
		ChangeNumber:      false,
		Gv1Migration:      false,
	}

	err = saveConfig(config.ConfigFile)
	log.Debugln("[textsecure] Crayfish registration done")
	transport.SetupTransporter(config.ConfigFile.Server, config.ConfigFile.UUID, registration.Registration.Password, config.ConfigFile.UserAgent, config.ConfigFile.ProxyServer)

	log.Debugln("[textsecure] generate keys")
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
	// config.ConfigFile = checkUUID(config.ConfigFile)
	saveConfig(config.ConfigFile)

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
func recID(source string) (string, error) {
	if len(source) == 0 {
		return "", errors.New("invalid recipient id")
	} else if len(source) > 0 && source[0] == '+' {
		log.Errorln("[textsecure] invalid recipient id", source)
		return source[1:], nil

	}
	return source, nil
}

// EndSessionFlag signals that this message resets the session
var EndSessionFlag uint32 = 1

// ProfileKeyUpdatedFlag signals that this message updates the profile key
var ProfileKeyUpdatedFlag = signalservice.DataMessage_PROFILE_KEY_UPDATE

func handleFlags(src string, dm *signalservice.DataMessage) (uint32, error) {
	flags := uint32(0)
	if dm.GetFlags() == uint32(signalservice.DataMessage_END_SESSION) {
		flags = EndSessionFlag
		srcClean, err := recID(src)
		if err != nil {
			return 0, err
		}
		textSecureStore.DeleteAllSessions(srcClean)
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

// decryptReceivedMessage decrypts a received message.
func decryptReceivedMessage(msg []byte) ([]byte, error) {
	// decrypt signalservice envelope
	macpos := len(msg) - 10
	tmac := msg[macpos:]
	aesKey := registration.Registration.SignalingKey[:32]
	macKey := registration.Registration.SignalingKey[32:]
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
			return nil, err
		}
	}

	return plaintext, nil
}

func createEnvelope(plaintext []byte) (*signalservice.Envelope, error) {
	env := &signalservice.Envelope{}
	err := proto.Unmarshal(plaintext, env)
	if err != nil {
		return nil, err
	}
	return env, nil
}

// Authenticate and decrypt a received message
func handleReceivedMessage(env *signalservice.Envelope) error {

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

			recid, err := recID(env.GetSourceE164())
			if err != nil {
				recid = env.GetSourceUuid()
			}
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
		b = stripPadding(b)
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
		b = stripPadding(b)
		err = handleMessage(env.GetSourceE164(), env.GetSourceUuid(), env.GetTimestamp(), b)
		if err != nil {
			return err
		}
	case signalservice.Envelope_UNIDENTIFIED_SENDER:

		if registration.Registration.SignalingKey[0] != 1 {
			log.Errorln("failed to handle message, signalingkey has wrong version, please re-register to update your signaling-key")
		}

		p, _ := proto.Marshal(env)
		data, err := crayfish.Instance.HandleEnvelope(p)
		if err != nil {
			return err
		}
		content, err := base64.StdEncoding.DecodeString(data.Message)
		if err != nil {
			return err
		}
		env.Content = content
		phoneNumber := "+" + strconv.FormatUint(data.Sender.PhoneNumber.Code.Value, 10) + strconv.FormatUint(data.Sender.PhoneNumber.National.Value, 10)
		log.Println("[textsecure] handleReceivedMessage:", phoneNumber, data.Sender.UUID)
		err = handleMessage(phoneNumber, data.Sender.UUID, uint64(data.Timestamp), content)
		if err != nil {
			return err
		}

	default:
		return MessageTypeNotImplementedError{uint32(*env.Type)}
	}

	return nil
}
