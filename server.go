// Copyright (c) 2014 Canonical Ltd.
// Copyright (c) 2020 Aaron Kimmig
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/signal-golang/textsecure/axolotl"
	signalservice "github.com/signal-golang/textsecure/protobuf"

	log "github.com/sirupsen/logrus"
)

var (
	SERVICE_REFLECTOR_HOST = "europe-west1-signal-cdn-reflector.cloudfunctions.net"
	SIGNAL_CDN_URL         = "https://cdn.signal.org"
	SIGNAL_CDN2_URL        = "https://cdn2.signal.org"

	createAccountPath = "/v1/accounts/%s/code/%s?client=%s"
	// CREATE_ACCOUNT_SMS_PATH   = "/v1/accounts/sms/code/%s?client=%s";
	CREATE_ACCOUNT_VOICE_PATH = "/v1/accounts/voice/code/%s"
	VERIFY_ACCOUNT_CODE_PATH  = "/v1/accounts/code/%s"
	registerUPSAccountPath    = "/v1/accounts/ups/"
	TURN_SERVER_INFO          = "/v1/accounts/turn"
	SET_ACCOUNT_ATTRIBUTES    = "/v1/accounts/attributes/"
	PIN_PATH                  = "/v1/accounts/pin/"
	REGISTRATION_LOCK_PATH    = "/v1/accounts/registration_lock"
	REQUEST_PUSH_CHALLENGE    = "/v1/accounts/fcm/preauth/%s/%s"
	WHO_AM_I                  = "/v1/accounts/whoami"
	SET_USERNAME_PATH         = "/v1/accounts/username/%s"
	DELETE_USERNAME_PATH      = "/v1/accounts/username"
	DELETE_ACCOUNT_PATH       = "/v1/accounts/me"

	allocateAttachmentPath   = "/v1/attachments/"
	attachmentPath           = "/v2/attachments/form/upload"
	ATTACHMENT_DOWNLOAD_PATH = "/v2/attachments/"

	prekeyMetadataPath = "/v2/keys/"
	prekeyPath         = "/v2/keys/%s"
	prekeyDevicePath   = "/v2/keys/%s/%s"
	signedPrekeyPath   = "/v2/keys/signed"

	provisioningCodePath    = "/v1/devices/provisioning/code"
	provisioningMessagePath = "/v1/provisioning/%s"
	devicePath              = "/v1/devices/%s"

	DIRECTORY_TOKENS_PATH   = "/v1/directory/tokens"
	DIRECTORY_VERIFY_PATH   = "/v1/directory/%s"
	DIRECTORY_AUTH_PATH     = "/v1/directory/auth"
	DIRECTORY_FEEDBACK_PATH = "/v1/directory/feedback-v3/%s"

	MESSAGE_PATH            = "/v1/messages/%s"
	acknowledgeMessagePath  = "/v1/messages/%s/%d"
	receiptPath             = "/v1/receipt/%s/%d"
	SENDER_ACK_MESSAGE_PATH = "/v1/messages/%s/%d"
	UUID_ACK_MESSAGE_PATH   = "/v1/messages/uuid/%s"
	ATTACHMENT_V2_PATH      = "/v2/attachments/form/upload"
	ATTACHMENT_V3_PATH      = "/v3/attachments/form/upload"

	PROFILE_PATH          = "/v1/profile/%s"
	PROFILE_USERNAME_PATH = "/v1/profile/username/%s"

	SENDER_CERTIFICATE_PATH         = "/v1/certificate/delivery?includeUuid=true"
	SENDER_CERTIFICATE_NO_E164_PATH = "/v1/certificate/delivery?includeUuid=true&includeE164=false"

	KBS_AUTH_PATH = "/v1/backup/auth"

	ATTACHMENT_KEY_DOWNLOAD_PATH = "/attachments/%s"
	ATTACHMENT_ID_DOWNLOAD_PATH  = "/attachments/%d"
	ATTACHMENT_UPLOAD_PATH       = "/attachments/"
	AVATAR_UPLOAD_PATH           = ""

	STICKER_MANIFEST_PATH = "/stickers/%s/manifest.proto"
	STICKER_PATH          = "/stickers/%s/full/%d"

	GROUPSV2_CREDENTIAL     = "/v1/certificate/group/%d/%d"
	GROUPSV2_GROUP          = "/v1/groups/"
	GROUPSV2_GROUP_PASSWORD = "/v1/groups/?inviteLinkPassword=%s"
	GROUPSV2_GROUP_CHANGES  = "/v1/groups/logs/%s"
	GROUPSV2_AVATAR_REQUEST = "/v1/groups/avatar/form"
	GROUPSV2_GROUP_JOIN     = "/v1/groups/join/%s"
	GROUPSV2_TOKEN          = "/v1/groups/token"

	SERVER_DELIVERED_TIMESTAMP_HEADER = "X-Signal-Timestamp"
)

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
	password       string
	registrationID uint32
	signalingKey   []byte
	captchaToken   string
}

var registrationInfo RegistrationInfo

// Registration

func requestCode(tel, method string) (string, error) {
	log.Infoln("[textsecure] request verification code for ", tel)
	resp, err := transport.get(fmt.Sprintf(createAccountPath, method, tel, "android"))
	if err != nil {
		fmt.Println(err.Error())
		return "", err
	}
	if resp.isError() {
		if resp.Status == 402 {
			log.Debugln(resp.Body)
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			newStr := buf.String()
			fmt.Printf(newStr)
			defer resp.Body.Close()

			return "", errors.New("Need to solve captcha")
		} else if resp.Status == 413 {
			log.Debugln(resp.Body)
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			newStr := buf.String()
			log.Debugln(newStr)
			defer resp.Body.Close()

			return "", errors.New("Rate Limit Exeded")
		} else {
			log.Debugln("[textsecure] request code status", resp.Status)
			defer resp.Body.Close()

			return "", errors.New("Error, see logs")
		}
	} else {
		defer resp.Body.Close()
		return "", nil
	}
	// unofficial dev method, useful for development, with no telephony account needed on the server
	// if method == "dev" {
	// 	code := make([]byte, 7)
	// 	l, err := resp.Body.Read(code)
	// 	if err == nil || (err == io.EOF && l == 7) {
	// 		return string(code[:3]) + string(code[4:]), nil
	// 	}
	// 	return "", err
	// }
	// return "", nil
}

// AccountAttributes describes what features are supported
type AccountAttributes struct {
	SignalingKey            string              `json:"signalingKey" yaml:"signalingKey"`
	RegistrationID          uint32              `json:"registrationId" yaml:"registrationId"`
	FetchesMessages         bool                `json:"fetchesMessages" yaml:"fetchesMessages"`
	Video                   bool                `json:"video" yaml:"video"`
	Voice                   bool                `json:"voice" yaml:"voice"`
	Pin                     string              `json:"pin" yaml:"pin"` // deprecated
	BasicStorageCredentials AuthCredentials     `json:"basicStorageCredentials" yaml:"basicStorageCredentials"`
	Capabilities            AccountCapabilities `json:"capabilities" yaml:"capabilities"`
	// UnidentifiedAccessKey          *byte `json:"unidentifiedAccessKey"`
	// UnrestrictedUnidentifiedAccess *bool `json:"unrestrictedUnidentifiedAccess"`
}

// AccountCapabilities describes what functions axolotl supports
type AccountCapabilities struct {
	UUID         bool `json:"uuid" yaml:"uuid"`
	Gv2          bool `json:"gv2" yaml:"gv2"`
	Storage      bool `json:"storage" yaml:"storage"`
	Gv1Migration bool `json:"gv1Migration" yaml:"gv1Migration"`
}

// AuthCredentials holds the credentials for the websocket connection
type AuthCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type RegistrationLockFailure struct {
	TimeRemaining uint32          `json:"timeRemaining"`
	Credentials   AuthCredentials `json:"backupCredentials"`
}

// verifyCode verificates the account with signal server
func verifyCode(code string, pin *string, credentials *AuthCredentials) (error, *AuthCredentials) {
	code = strings.Replace(code, "-", "", -1)

	vd := AccountAttributes{
		SignalingKey:    base64.StdEncoding.EncodeToString(registrationInfo.signalingKey),
		RegistrationID:  registrationInfo.registrationID,
		FetchesMessages: true,
		Voice:           false,
		Video:           false,
		Capabilities: AccountCapabilities{
			UUID:         true,
			Gv2:          true,
			Storage:      false,
			Gv1Migration: false,
		},
		// Pin:             nil,
		// UnidentifiedAccessKey:          nil,
		// UnrestrictedUnidentifiedAccess: nil,
	}
	if pin != nil {
		vd.Pin = *pin
		vd.BasicStorageCredentials = *credentials
	}
	log.Debugln("[textsecure] verifyCode", vd)
	body, err := json.Marshal(vd)
	if err != nil {
		return err, nil
	}
	resp, err := transport.putJSON(fmt.Sprintf(VERIFY_ACCOUNT_CODE_PATH, code), body)
	if err != nil {
		fmt.Println(err.Error())
		return err, nil
	}
	if resp.isError() {

		if resp.Status == 423 {
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			newStr := buf.String()
			fmt.Printf(newStr)
			v := RegistrationLockFailure{}
			err := json.Unmarshal([]byte(newStr), &v)
			log.Debugln("v", v)

			if err != nil {
				return err, nil
			}
			return fmt.Errorf(fmt.Sprintf("RegistrationLockFailure \n Time to wait \n %s", newStr)), &v.Credentials
		} else {
			return resp, nil
		}
	}
	config.AccountCapabilities = vd.Capabilities
	return nil, nil
}

type upsRegistration struct {
	UPSRegistrationID string `json:"upsRegistrationId"`
}

// RegisterWithUPS registers our Ubuntu push client token with the server.
func RegisterWithUPS(token string) error {
	reg := upsRegistration{
		UPSRegistrationID: token,
	}
	body, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	resp, err := transport.putJSON(registerUPSAccountPath, body)
	if err != nil {
		return err
	}
	if resp.isError() {
		return resp
	}
	return nil
}

// SetAccountAttributes updates the account attributes
func SetAccountAttributes(attributes *AccountAttributes) error {
	log.Debugln("[textsecure] setAccountAttributes")
	body, err := json.Marshal(attributes)
	if err != nil {
		return err
	}
	resp, err := transport.putJSON(SET_ACCOUNT_ATTRIBUTES, body)
	if err != nil {
		return err
	}
	if resp.isError() {
		return resp
	}
	return nil
}

type whoAmIResponse struct {
	UUID string `json:"uuid"`
}

func GetMyUUID() (string, error) {
	log.Debugln("[textsecure] get my uuid")
	resp, err := transport.get(WHO_AM_I)
	if err != nil {
		return "", err
	}
	if resp.isError() {
		return "", resp
	}
	dec := json.NewDecoder(resp.Body)
	var response whoAmIResponse
	dec.Decode(&response)
	return response.UUID, nil
}

type jsonDeviceCode struct {
	VerificationCode string `json:"verificationCode"`
}

func getNewDeviceVerificationCode() (string, error) {
	resp, err := transport.get(provisioningCodePath)
	if err != nil {
		return "", err
	}
	dec := json.NewDecoder(resp.Body)
	var c jsonDeviceCode
	dec.Decode(&c)
	return c.VerificationCode, nil
}

type DeviceInfo struct {
	ID       uint32 `json:"id"`
	Name     string `json:"name"`
	Created  uint64 `json:"created"`
	LastSeen uint64 `json:"lastSeen"`
}
type jsonDevices struct {
	DeviceList []DeviceInfo `json:"devices"`
}

func getLinkedDevices() ([]DeviceInfo, error) {

	devices := &jsonDevices{}

	resp, err := transport.get(fmt.Sprintf(devicePath, ""))
	if err != nil {
		return devices.DeviceList, err
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&devices)
	if err != nil {
		return devices.DeviceList, nil
	}

	return devices.DeviceList, nil
}

func unlinkDevice(id int) error {
	_, err := transport.del(fmt.Sprintf(devicePath, strconv.Itoa(id)))
	if err != nil {
		return err
	}
	return nil
}

func addNewDevice(ephemeralId, publicKey, verificationCode string) error {
	decPk, err := decodeKey(publicKey)
	if err != nil {
		return err
	}

	theirPublicKey := axolotl.NewECPublicKey(decPk)

	pm := &signalservice.ProvisionMessage{
		IdentityKeyPublic:  identityKey.PublicKey.Serialize(),
		IdentityKeyPrivate: identityKey.PrivateKey.Key()[:],
		Number:             &config.Tel,
		ProvisioningCode:   &verificationCode,
	}

	ciphertext, err := provisioningCipher(pm, theirPublicKey)
	if err != nil {
		return err
	}

	jsonBody := make(map[string]string)
	jsonBody["body"] = base64.StdEncoding.EncodeToString(ciphertext)
	body, err := json.Marshal(jsonBody)
	if err != nil {
		return err
	}

	url := fmt.Sprintf(provisioningMessagePath, ephemeralId)
	resp, err := transport.putJSON(url, body)
	if err != nil {
		return err
	}
	if resp.isError() {
		return resp
	}
	return nil
}

// Profile describes the profile type
type Profile struct {
	IdentityKey                    string          `json:"identityKey"`
	Name                           string          `json:"name"`
	Avatar                         string          `json:"avatar"`
	UnidentifiedAccess             string          `json:"unidentifiedAccess"`
	UnrestrictedUnidentifiedAccess bool            `json:"unrestrictedUnidentifiedAccess"`
	Capabilities                   ProfileSettings `json:"capabilities"`
	Username                       string          `json:"username"`
	UUID                           string          `json:"uuid"`
	Payments                       string          `json:"payments"`
	Credential                     string          `json:"credential"`
}

// ProfileSettings contains the settings for the profile
type ProfileSettings struct {
	UUID         bool `json:"uuid"`
	Gv2          bool `json:"gv2"`
	Gv1Migration bool `json:"gv1-migration"`
}

// GetProfileE164 get a profile by a phone number
func GetProfileE164(tel string) (Contact, error) {

	resp, err := transport.get(fmt.Sprintf(PROFILE_PATH, tel))
	if err != nil {
		log.Debugln(err)
	}

	profile := &Profile{}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&profile)
	if err != nil {
		log.Debugln(err)
	}
	avatar, _ := GetAvatar(profile.Avatar)
	buf := new(bytes.Buffer)
	buf.ReadFrom(avatar)

	c := contacts[profile.UUID]
	avatarDecrypted, err := decryptAvatar(buf.Bytes(), []byte(profile.IdentityKey))
	if err != nil {
		log.Debugln(err)
	}
	c.Username = profile.Username
	c.UUID = profile.UUID
	c.Avatar = avatarDecrypted
	contacts[c.UUID] = c
	WriteContactsToPath()
	return c, nil
}

var cdnTransport *httpTransporter

func setupCDNTransporter() {
	// setupCA()
	cdnTransport = newHTTPTransporter(SIGNAL_CDN_URL, config.Tel, registrationInfo.password)
}

// GetAvatar retuns an avatar for it's url from signal cdn
func GetAvatar(avatarURL string) (io.ReadCloser, error) {
	log.Debugln("[textsecure] get avatar from ", avatarURL)

	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	c := &http.Client{Transport: customTransport}
	req, err := http.NewRequest("GET", SIGNAL_CDN_URL+"/"+avatarURL, nil)
	req.Header.Add("Host", SERVICE_REFLECTOR_HOST)
	req.Header.Add("Content-Type", "application/octet-stream")
	resp, err := c.Do(req)
	if err != nil {
		log.Debugln("[textsecure] getAvatar ", err)

		return nil, err
	}

	return resp.Body, nil
}

func decryptAvatar(avatar []byte, identityKey []byte) ([]byte, error) {

	l := len(avatar[:]) - 30
	b, err := aesCtrNoPaddingDecrypt(identityKey[:16], avatar[:l])
	if err != nil {
		return nil, err
	}
	return b, nil
}

// PUT /v2/keys/
func registerPreKeys() error {
	body, err := json.MarshalIndent(preKeys, "", "")
	if err != nil {
		return err
	}

	resp, err := transport.putJSON(prekeyMetadataPath, body)
	if err != nil {
		return err
	}
	if resp.isError() {
		return resp
	}
	return nil
}

// GET /v2/keys/{number}/{device_id}?relay={relay}
func getPreKeys(UUID string, deviceID string) (*preKeyResponse, error) {
	resp, err := transport.get(fmt.Sprintf(prekeyDevicePath, UUID, deviceID))
	if err != nil {
		return nil, err
	}
	if resp.isError() {
		return nil, resp
	}
	dec := json.NewDecoder(resp.Body)
	k := &preKeyResponse{}
	dec.Decode(k)
	return k, nil
}

// jsonContact is the data returned by the server for each registered contact
type jsonContact struct {
	Token string `json:"token"`
	Voice string `json:"voice"`
	Video string `json:"video"`
}
type jsonContacts struct {
	Contacts []jsonContact `json:"contacts"`
}

// GetRegisteredContacts returns the subset of the local contacts
// that are also registered with the server

func GetRegisteredContacts() ([]Contact, error) {
	lc, err := client.GetLocalContacts()
	if err != nil {
		return nil, fmt.Errorf("could not get local contacts :%s", err)
	}
	tokens := make([]string, len(lc))
	m := make(map[string]Contact)
	// todo deduplicate contacts
	for i, c := range lc {
		t := telToToken(c.Tel)
		tokens[i] = t
		m[t] = c
	}

	contacts := make(map[string][]string)
	contacts["contacts"] = tokens
	body, err := json.MarshalIndent(contacts, "", "    ")
	if err != nil {
		return nil, err
	}
	resp, err := transport.putJSON(DIRECTORY_TOKENS_PATH, body)
	// // TODO: breaks when there is no internet
	if resp != nil && resp.Status == 413 {
		log.Println("[textsecure] Rate limit exceeded while refreshing contacts: 413")
		return nil, errors.New("Refreshing contacts: rate limit exceeded: 413")
	}
	if err != nil {
		return nil, err
	}
	if resp.isError() {
		return nil, resp
	}
	dec := json.NewDecoder(resp.Body)
	var jc jsonContacts
	dec.Decode(&jc)
	lc = make([]Contact, len(jc.Contacts))
	for i, c := range jc.Contacts {
		lc[i] = m[c.Token]
	}
	return lc, nil
}

// Attachment handling

type jsonAllocation struct {
	ID       uint64 `json:"id"`
	Location string `json:"location"`
}

// GET /v1/attachments/
func allocateAttachment() (uint64, string, error) {
	resp, err := transport.get(allocateAttachmentPath)
	if err != nil {
		return 0, "", err
	}
	dec := json.NewDecoder(resp.Body)
	var a jsonAllocation
	dec.Decode(&a)
	return a.ID, a.Location, nil
}

func getAttachmentLocation(id uint64, key string, cdnNumber uint32) (string, error) {
	cdn := SIGNAL_CDN_URL
	if cdnNumber == 2 {
		cdn = SIGNAL_CDN2_URL
	}
	if id != 0 {
		return cdn + fmt.Sprintf(ATTACHMENT_ID_DOWNLOAD_PATH, id), nil
	}
	return cdn + fmt.Sprintf(ATTACHMENT_KEY_DOWNLOAD_PATH, key), nil
}

func getProfileLocation(profilePath string) (string, error) {
	cdn := SIGNAL_CDN_URL
	return cdn + fmt.Sprintf(profilePath), nil
}

// Messages

type jsonMessage struct {
	Type               int32  `json:"type"`
	DestDeviceID       uint32 `json:"destinationDeviceId"`
	DestRegistrationID uint32 `json:"destinationRegistrationId"`
	Content            string `json:"content"`
	Relay              string `json:"relay,omitempty"`
}

func createMessage(msg *outgoingMessage) *signalservice.DataMessage {
	dm := &signalservice.DataMessage{}
	now := uint64(time.Now().UnixNano() / 1000000)
	if msg.timestamp != nil {
		now = *msg.timestamp
	}

	dm.Timestamp = &now
	if msg.msg != "" {
		dm.Body = &msg.msg
	}
	dm.ExpireTimer = &msg.expireTimer
	if msg.attachment != nil {
		id := signalservice.AttachmentPointer_CdnId{
			CdnId: msg.attachment.id,
		}
		dm.Attachments = []*signalservice.AttachmentPointer{
			{
				AttachmentIdentifier: &id,
				ContentType:          &msg.attachment.ct,
				Key:                  msg.attachment.keys[:],
				Digest:               msg.attachment.digest[:],
				Size:                 &msg.attachment.size,
			},
		}
		if msg.attachment.voiceNote {
			var flag uint32 = 1
			dm.Attachments[0].Flags = &flag
		}
	}
	if msg.group != nil {
		dm.Group = &signalservice.GroupContext{
			Id:          msg.group.id,
			Type:        &msg.group.typ,
			Name:        &msg.group.name,
			MembersE164: msg.group.members,
		}
	}
	if msg.groupV2 != nil {
		dm.GroupV2 = msg.groupV2
	}

	dm.Flags = &msg.flags

	return dm
}

func padMessage(msg []byte) []byte {
	l := (len(msg) + 160)
	l = l - l%160
	n := make([]byte, l)
	copy(n, msg)
	n[len(msg)] = 0x80
	return n
}

func stripPadding(msg []byte) []byte {
	for i := len(msg) - 1; i >= 0; i-- {
		if msg[i] == 0x80 {
			return msg[:i]
		}
	}
	return msg
}

func makePreKeyBundle(UUID string, deviceID uint32) (*axolotl.PreKeyBundle, error) {
	pkr, err := getPreKeys(UUID, strconv.Itoa(int(deviceID)))
	if err != nil {
		return nil, err
	}

	if len(pkr.Devices) != 1 {
		return nil, fmt.Errorf("no prekeys for contact %s, device %d", UUID, deviceID)
	}

	d := pkr.Devices[0]

	if d.PreKey == nil {
		return nil, fmt.Errorf("no prekey for contact %s, device %d", UUID, deviceID)
	}

	decPK, err := decodeKey(d.PreKey.PublicKey)
	if err != nil {
		return nil, err
	}

	if d.SignedPreKey == nil {
		return nil, fmt.Errorf("no signed prekey for contact %s, device %d", UUID, deviceID)
	}

	decSPK, err := decodeKey(d.SignedPreKey.PublicKey)
	if err != nil {
		return nil, err
	}

	decSig, err := decodeSignature(d.SignedPreKey.Signature)
	if err != nil {
		return nil, err
	}

	decIK, err := decodeKey(pkr.IdentityKey)
	if err != nil {
		return nil, err
	}

	pkb, err := axolotl.NewPreKeyBundle(
		d.RegistrationID, d.DeviceID, d.PreKey.ID,
		axolotl.NewECPublicKey(decPK), int32(d.SignedPreKey.ID), axolotl.NewECPublicKey(decSPK),
		decSig, axolotl.NewIdentityKey(decIK))
	if err != nil {
		return nil, err
	}

	return pkb, nil
}

func buildMessage(reciever string, paddedMessage []byte, devices []uint32, isSync bool) ([]jsonMessage, error) {
	recid := recID(reciever)
	messages := []jsonMessage{}

	for _, devid := range devices {
		if !textSecureStore.ContainsSession(recid, devid) {
			pkb, err := makePreKeyBundle(reciever, devid)
			if err != nil {
				return nil, err
			}
			sb := axolotl.NewSessionBuilder(textSecureStore, textSecureStore, textSecureStore, textSecureStore, recid, pkb.DeviceID)
			err = sb.BuildSenderSession(pkb)
			if err != nil {
				return nil, err
			}
		}
		sc := axolotl.NewSessionCipher(textSecureStore, textSecureStore, textSecureStore, textSecureStore, recid, devid)
		encryptedMessage, messageType, err := sc.SessionEncryptMessage(paddedMessage)
		if err != nil {
			return nil, err
		}

		rrID, err := sc.GetRemoteRegistrationID()
		if err != nil {
			return nil, err
		}

		jmsg := jsonMessage{
			Type:               messageType,
			DestDeviceID:       devid,
			DestRegistrationID: rrID,
		}

		jmsg.Content = base64.StdEncoding.EncodeToString(encryptedMessage)
		messages = append(messages, jmsg)
	}

	return messages, nil
}

var (
	mismatchedDevicesStatus = 409
	staleDevicesStatus      = 410
	rateLimitExceededStatus = 413
)

type jsonMismatchedDevices struct {
	MissingDevices []uint32 `json:"missingDevices"`
	ExtraDevices   []uint32 `json:"extraDevices"`
}

type jsonStaleDevices struct {
	StaleDevices []uint32 `json:"staleDevices"`
}

type sendMessageResponse struct {
	NeedsSync bool   `json:"needsSync"`
	Timestamp uint64 `json:"-"`
}

// ErrRemoteGone is returned when the peer reinstalled and lost its session state.
var ErrRemoteGone = errors.New("the remote device is gone (probably reinstalled)")

var deviceLists = map[string][]uint32{}

func buildAndSendMessage(uuid string, paddedMessage []byte, isSync bool, timestamp *uint64) (*sendMessageResponse, error) {
	bm, err := buildMessage(uuid, paddedMessage, deviceLists[uuid], isSync)
	if err != nil {
		return nil, err
	}
	m := make(map[string]interface{})
	m["messages"] = bm
	if timestamp == nil {
		now := uint64(time.Now().UnixNano() / 1000000)
		timestamp = &now
	}
	m["timestamp"] = timestamp
	m["destination"] = uuid
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	resp, err := transport.putJSON(fmt.Sprintf(MESSAGE_PATH, uuid), body)
	if err != nil {
		return nil, err
	}

	if resp.Status == mismatchedDevicesStatus {
		dec := json.NewDecoder(resp.Body)
		var j jsonMismatchedDevices
		dec.Decode(&j)
		log.Debugf("[textsecure] Mismatched devices: %+v\n", j)
		devs := []uint32{}
		for _, id := range deviceLists[uuid] {
			in := true
			for _, eid := range j.ExtraDevices {
				if id == eid {
					in = false
					break
				}
			}
			if in {
				devs = append(devs, id)
			}
		}
		deviceLists[uuid] = append(devs, j.MissingDevices...)
		return buildAndSendMessage(uuid, paddedMessage, isSync, timestamp)
	}
	if resp.Status == staleDevicesStatus {
		dec := json.NewDecoder(resp.Body)
		var j jsonStaleDevices
		dec.Decode(&j)
		log.Debugf("[textsecure] Stale devices: %+v\n", j)
		for _, id := range j.StaleDevices {
			textSecureStore.DeleteSession(recID(uuid), id)
		}
		return buildAndSendMessage(uuid, paddedMessage, isSync, timestamp)
	}
	if resp.isError() {
		return nil, resp
	}

	var smRes sendMessageResponse
	dec := json.NewDecoder(resp.Body)
	dec.Decode(&smRes)
	smRes.Timestamp = *timestamp

	log.Debugf("[textsecure] SendMessageResponse: %+v\n", smRes)
	return &smRes, nil
}

func sendMessage(msg *outgoingMessage) (uint64, error) {
	if _, ok := deviceLists[msg.destination]; !ok {
		deviceLists[msg.destination] = []uint32{1}
	}

	dm := createMessage(msg)

	content := &signalservice.Content{
		DataMessage: dm,
	}
	b, err := proto.Marshal(content)
	if err != nil {
		return 0, err
	}

	resp, err := buildAndSendMessage(msg.destination, padMessage(b), false, dm.Timestamp)
	if err != nil {
		return 0, err
	}

	if resp.NeedsSync {
		log.Debugf("[textsecure] Needs sync. destination: %s", msg.destination)
		sm := &signalservice.SyncMessage{
			Sent: &signalservice.SyncMessage_Sent{
				DestinationE164: &msg.destination,
				Timestamp:       dm.Timestamp,
				Message:         dm,
			},
		}

		_, serr := sendSyncMessage(sm, dm.Timestamp)
		if serr != nil {
			log.WithFields(log.Fields{
				"error":       serr,
				"destination": msg.destination,
				"timestamp":   resp.Timestamp,
			}).Error("Failed to send sync message")
		}
	}

	return resp.Timestamp, err
}

// TODO switch to uuids
func sendSyncMessage(sm *signalservice.SyncMessage, timestamp *uint64) (uint64, error) {
	log.Debugln("[textsecure] sendSyncMessage", sm.Request.Type)
	user := config.Tel
	if config.UUID != "" {
		user = config.UUID
	}
	if _, ok := deviceLists[user]; !ok {
		deviceLists[user] = []uint32{1}
	}

	content := &signalservice.Content{
		SyncMessage: sm,
	}

	b, err := proto.Marshal(content)
	if err != nil {
		return 0, err
	}

	resp, err := buildAndSendMessage(user, padMessage(b), true, timestamp)
	return resp.Timestamp, err
}
