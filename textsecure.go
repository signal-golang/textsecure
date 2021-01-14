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
	"strings"

	"bytes"

	"github.com/signal-golang/mimemagic"

	"github.com/golang/protobuf/proto"

	"github.com/signal-golang/textsecure/axolotl"
	"github.com/signal-golang/textsecure/groupsv2"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	log "github.com/sirupsen/logrus"
)

// Generate a random 16 byte string used for HTTP Basic Authentication to the server
func generatePassword() string {
	b := make([]byte, 16)
	randBytes(b[:])
	return base64EncWithoutPadding(b)
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

// Base64-encodes without padding the result
func base64EncWithoutPadding(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	return strings.TrimRight(s, "=")
}

// Base64-decodes a non-padded string
func base64DecodeNonPadded(s string) ([]byte, error) {
	if len(s)%4 != 0 {
		s = s + strings.Repeat("=", 4-len(s)%4)
	}
	return base64.StdEncoding.DecodeString(s)
}

func encodeKey(key []byte) string {
	return base64EncWithoutPadding(append([]byte{5}, key[:]...))
}

// ErrBadPublicKey is raised when a given public key is not in the
// expected format.
var ErrBadPublicKey = errors.New("public key not formatted correctly")

func decodeKey(s string) ([]byte, error) {
	b, err := base64DecodeNonPadded(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 33 || b[0] != 5 {
		return nil, ErrBadPublicKey
	}
	return b[1:], nil
}

func decodeSignature(s string) ([]byte, error) {
	b, err := base64DecodeNonPadded(s)
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
	GetConfig             func() (*Config, error)
	GetLocalContacts      func() ([]Contact, error)
	MessageHandler        func(*Message)
	TypingMessageHandler  func(*Message)
	ReceiptMessageHandler func(*Message)
	CallMessageHandler    func(*Message)
	ReceiptHandler        func(string, uint32, uint64)
	SyncReadHandler       func(string, uint64)
	SyncSentHandler       func(*Message, uint64)
	RegistrationDone      func()
}

var (
	config *Config
	client *Client
)

// setupLogging sets the logging verbosity level based on configuration
// and environment variables
func setupLogging() {
	loglevel := config.LogLevel
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

	config, err = loadConfig()
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
	setupTransporter()
	setupCDNTransporter()
	identityKey, err = textSecureStore.GetIdentityKeyPair()
	// check if we have a uuid and if not get it
	config = checkUUID(config)
	GetProfile(config.UUID)
	return err
}

func registerDevice() error {
	if config.Tel == "" {
		config.Tel = client.GetPhoneNumber()
		if config.Tel == "" {
			return errors.New("empty phone number")
		}
	}
	setupTransporter()
	code, err := requestCode(config.Tel, config.VerificationType)
	if err != nil {
		return err
	}
	if config.VerificationType != "dev" {
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
	client.RegistrationDone()
	if client.RegistrationDone != nil {
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

func handleMessage(srcE164 string, srcUUID string, timestamp uint64, b []byte) error {
	b = stripPadding(b)

	content := &signalservice.Content{}
	err := proto.Unmarshal(b, content)
	if err != nil {
		return err
	}

	if dm := content.GetDataMessage(); dm != nil {
		return handleDataMessage(srcE164, srcUUID, timestamp, dm)
	} else if sm := content.GetSyncMessage(); sm != nil && config.Tel == srcE164 {
		return handleSyncMessage(srcUUID, timestamp, sm)
	} else if cm := content.GetCallMessage(); cm != nil {
		return handleCallMessage(srcUUID, timestamp, cm)
	} else if rm := content.GetReceiptMessage(); rm != nil {
		return handleReceiptMessage(srcUUID, timestamp, rm)
	} else if tm := content.GetTypingMessage(); tm != nil {
		return handleTypingMessage(srcUUID, timestamp, tm)
	} else if nm := content.GetNullMessage(); nm != nil {
		log.Errorln("[textsecure] Nullmessage content received", content)

		return nil
	}

	//FIXME get the right content
	// log.Errorf(content)
	log.Errorln("[textsecure] Unknown message content received", content)
	return nil
}

// EndSessionFlag signals that this message resets the session
var EndSessionFlag uint32 = 1

func handleFlags(src string, dm *signalservice.DataMessage) (uint32, error) {
	flags := uint32(0)
	if dm.GetFlags() == uint32(signalservice.DataMessage_END_SESSION) {
		flags = EndSessionFlag

		textSecureStore.DeleteAllSessions(recID(src))
		textSecureStore.DeleteAllSessions(src)
	}
	return flags, nil
}

// handleDataMessage handles an incoming DataMessage and calls client callbacks
func handleDataMessage(src string, srcUUID string, timestamp uint64, dm *signalservice.DataMessage) error {
	flags, err := handleFlags(src, dm)
	if err != nil {
		return err
	}

	atts, err := handleAttachments(dm)
	if err != nil {
		return err
	}
	log.Debugln("[textsecure] handleDataMessage", timestamp, *dm.Timestamp, dm.GetExpireTimer())
	gr, err := handleGroups(src, dm)
	if err != nil {
		return err
	}
	gr2, err := groupsv2.HandleGroupsV2(src, dm)
	if err != nil {
		return err
	}
	if gr2 != nil {
		if gr2.DecryptedGroup.PendingMembers != nil {
			groupAction := groupsv2.CreateRequestForGroup(gr2.Hexid, gr2.DecryptedGroup.PendingMembers[0].Uuid)
			authorization, err := groupsv2.NewGroupsV2AuthorizationForGroup(gr2.DecryptedGroup.PendingMembers[0].Uuid, gr2.Hexid)
			if err != nil {
				log.Errorln("[textsecure] pacth gro", err)
			} else {
				log.Errorln("[textsecure] Yeai", err)

				PatchGroupV2(groupAction, authorization)
			}

		}
	}
	msg := &Message{
		sourceUUID:  srcUUID,
		source:      src,
		message:     dm.GetBody(),
		attachments: atts,
		group:       gr,
		groupV2:     gr2,
		flags:       flags,
		expireTimer: dm.GetExpireTimer(),
		profileKey:  dm.GetProfileKey(),
		timestamp:   *dm.Timestamp,
		quote:       dm.GetQuote(),
		contact:     dm.GetContact(),
		preview:     dm.GetPreview(),
		sticker:     dm.GetSticker(),
		reaction:    dm.GetReaction(),
		// requiredProtocolVersion: dm.GetRequiredProtocolVersion(),
		// isViewOnce: *dm.IsViewOnce,
	}

	if client.MessageHandler != nil {
		client.MessageHandler(msg)
	}
	return nil
}
func handleCallMessage(src string, timestamp uint64, cm *signalservice.CallMessage) error {

	msg := &Message{
		source:    src,
		message:   "callMessage",
		timestamp: timestamp,
	}

	if client.MessageHandler != nil {
		client.MessageHandler(msg)
	}
	return nil
}
func handleTypingMessage(src string, timestamp uint64, cm *signalservice.TypingMessage) error {

	msg := &Message{
		source:    src,
		message:   "typingMessage",
		timestamp: timestamp,
	}

	if client.TypingMessageHandler != nil {
		client.TypingMessageHandler(msg)
	}
	return nil
}
func handleReceiptMessage(src string, timestamp uint64, cm *signalservice.ReceiptMessage) error {
	msg := &Message{
		source:    src,
		message:   "sentReceiptMessage",
		timestamp: cm.GetTimestamp()[0],
	}
	if *cm.Type == signalservice.ReceiptMessage_READ {
		msg.message = "readReceiptMessage"
	}
	if *cm.Type == signalservice.ReceiptMessage_DELIVERY {
		msg.message = "deliveryReceiptMessage"
	}
	if client.ReceiptMessageHandler != nil {
		client.ReceiptMessageHandler(msg)
	}

	return nil
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
	macpos := len(msg) - 10
	tmac := msg[macpos:]
	aesKey := registrationInfo.signalingKey[:32]
	macKey := registrationInfo.signalingKey[32:]
	if !axolotl.ValidTruncMAC(msg[:macpos], tmac, macKey) {
		return ErrInvalidMACForMessage
	}
	ciphertext := msg[1:macpos]
	plaintext, err := axolotl.Decrypt(aesKey, ciphertext)
	if err != nil {
		return err
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
	default:
		return MessageTypeNotImplementedError{uint32(*env.Type)}
	}

	return nil
}
