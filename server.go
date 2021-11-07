// Copyright (c) 2014 Canonical Ltd.
// Copyright (c) 2020 Aaron Kimmig
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/signal-golang/textsecure/axolotl"
	"github.com/signal-golang/textsecure/config"
	"github.com/signal-golang/textsecure/contactDiscoveryCrypto"
	"github.com/signal-golang/textsecure/contacts"
	"github.com/signal-golang/textsecure/contactsDiscovery"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	"github.com/signal-golang/textsecure/registration"
	"github.com/signal-golang/textsecure/unidentifiedAccess"

	"github.com/signal-golang/textsecure/transport"

	log "github.com/sirupsen/logrus"
)

var (
	SERVICE_REFLECTOR_HOST = "europe-west1-signal-cdn-reflector.cloudfunctions.net"
	SIGNAL_CDN_URL         = "https://cdn.signal.org"
	SIGNAL_CDN2_URL        = "https://cdn2.signal.org"
	DIRECTORY_URL          = "https://api.directory.signal.org"
	STORAGE_URL            = "https://storage.signal.org"

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

	SENDER_CERTIFICATE_PATH         = "/v1/certificate/delivery"
	SENDER_CERTIFICATE_NO_E164_PATH = "/v1/certificate/delivery?includeE164=false"

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

	ATTESTATION_REQUEST = "/v1/attestation/%s"
	DISCOVERY_REQUEST   = "/v1/discovery/%s"

	SERVER_DELIVERED_TIMESTAMP_HEADER = "X-Signal-Timestamp"
	CDS_MRENCLAVE                     = "c98e00a4e3ff977a56afefe7362a27e4961e4f19e211febfbb19b897e6b80b15"

	CONTACT_DISCOVERY = "/v1/discovery/%s"
)

// Registration
const (
	responseNeedCaptcha int = 402
	responseRateLimit   int = 413
)

func requestCode(tel, method, captcha string) (string, *int, error) {
	log.Infoln("[textsecure] request verification code for ", tel)
	path := fmt.Sprintf(createAccountPath, method, tel, "android")
	if captcha != "" {
		path += "&captcha=" + captcha
	}
	resp, err := transport.Transport.Get(path)
	if err != nil {
		log.Errorln("[textsecure] requestCode", err)
		return "", nil, err
	}
	if resp.IsError() {
		if resp.Status == 402 {
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			newStr := buf.String()
			log.Errorln("[textsecure] requestCode", newStr)
			defer resp.Body.Close()

			return "", &resp.Status, errors.New("Need to solve captcha")
		} else if resp.Status == 413 {
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			newStr := buf.String()
			log.Errorln("[textsecure] requestCode", newStr)
			defer resp.Body.Close()

			return "", &resp.Status, errors.New("Rate limit exeded")
		} else {
			log.Debugln("[textsecure] request code status", resp.Status)
			defer resp.Body.Close()

			return "", nil, errors.New("Error, see logs")
		}
	} else {
		defer resp.Body.Close()
		return "", nil, nil
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
	SignalingKey                   string                     `json:"signalingKey" yaml:"signalingKey"`
	FetchesMessages                bool                       `json:"fetchesMessages" yaml:"fetchesMessages"`
	RegistrationID                 uint32                     `json:"registrationId" yaml:"registrationId"`
	Name                           string                     `json:"name" yaml:"name"`
	Video                          bool                       `json:"video" yaml:"video"`
	Voice                          bool                       `json:"voice" yaml:"voice"`
	Pin                            *string                    `json:"pin" yaml:"pin"` // deprecated
	BasicStorageCredentials        transport.AuthCredentials  `json:"basicStorageCredentials" yaml:"basicStorageCredentials"`
	Capabilities                   config.AccountCapabilities `json:"capabilities" yaml:"capabilities"`
	DiscoverableByPhoneNumber      bool                       `json:"discoverableByPhoneNumber" yaml:"discoverableByPhoneNumber"`
	UnrestrictedUnidentifiedAccess bool                       `json:"unrestrictedUnidentifiedAccess"`
	UnidentifiedAccessKey          *[]byte                    `json:"unidentifiedAccessKey"`
}

type UpdateAccountAttributes struct {
	SignalingKey                   *string                    `json:"signalingKey" yaml:"signalingKey"`
	FetchesMessages                bool                       `json:"fetchesMessages" yaml:"fetchesMessages"`
	RegistrationID                 uint32                     `json:"registrationId" yaml:"registrationId"`
	Name                           string                     `json:"name" yaml:"name"`
	Pin                            *string                    `json:"pin" yaml:"pin"` // deprecated
	RegistrationLock               *string                    `json:"registrationLock" yaml:"registrationLock"`
	UnidentifiedAccessKey          *[]byte                    `json:"unidentifiedAccessKey"`
	UnrestrictedUnidentifiedAccess bool                       `json:"unrestrictedUnidentifiedAccess"`
	Capabilities                   config.AccountCapabilities `json:"capabilities" yaml:"capabilities"`
	DiscoverableByPhoneNumber      bool                       `json:"discoverableByPhoneNumber" yaml:"discoverableByPhoneNumber"`
	Video                          bool                       `json:"video" yaml:"video"`
	Voice                          bool                       `json:"voice" yaml:"voice"`
}

type RegistrationLockFailure struct {
	TimeRemaining uint32                    `json:"timeRemaining"`
	Credentials   transport.AuthCredentials `json:"backupCredentials"`
}

// verifyCode verificates the account with signal server
func verifyCode(code string, pin *string, credentials *transport.AuthCredentials) (*transport.AuthCredentials, error) {
	code = strings.Replace(code, "-", "", -1)
	key := identityKey.PrivateKey.Key()[:]
	unidentifiedAccessKey, err := unidentifiedAccess.DeriveAccessKeyFrom(key)
	if err != nil {
		log.Debugln("[textsecure] verifyCode", err)
	}
	vd := AccountAttributes{
		SignalingKey:    base64.StdEncoding.EncodeToString(registration.Registration.SignalingKey),
		RegistrationID:  registration.Registration.RegistrationID,
		FetchesMessages: true,
		Voice:           false,
		Video:           false,
		Pin:             nil,
		Name:            config.ConfigFile.Name,
		Capabilities: config.AccountCapabilities{
			UUID:    false,
			Gv2:     true,
			Storage: false,
		},
		DiscoverableByPhoneNumber:      true,
		UnidentifiedAccessKey:          &unidentifiedAccessKey,
		UnrestrictedUnidentifiedAccess: false,
		// Pin:             nil,
	}
	if pin != nil {
		vd.Pin = pin
		vd.BasicStorageCredentials = *credentials
	}
	log.Debugln("[textsecure] verifyCode", vd)
	body, err := json.Marshal(vd)
	if err != nil {
		return nil, err
	}
	resp, err := transport.Transport.PutJSON(fmt.Sprintf(VERIFY_ACCOUNT_CODE_PATH, code), body)
	if err != nil {
		log.Errorln("[textsecure] verifyCode", err)
		return nil, err
	}
	if resp.IsError() {

		if resp.Status == 423 {
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			newStr := buf.String()
			log.Errorln("[textsecure] verifyCode", newStr)
			v := RegistrationLockFailure{}
			err := json.Unmarshal([]byte(newStr), &v)
			if err != nil {
				return nil, err
			}
			return &v.Credentials, fmt.Errorf(fmt.Sprintf("RegistrationLockFailure \n Time to wait \n %s", newStr))
		} else {
			// todo extract uuid from resp.Body
			return nil, resp
		}
	}
	// extract uuid
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	newStr := buf.String()
	log.Errorln("[textsecure] successful registration", newStr)
	defer resp.Body.Close()

	config.ConfigFile.AccountCapabilities = vd.Capabilities
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
	resp, err := transport.Transport.PutJSON(registerUPSAccountPath, body)
	if err != nil {
		return err
	}
	if resp.IsError() {
		return resp
	}
	return nil
}

// SetAccountCapabilities lets the client decide when it's ready for new functions to support for example groupsv2
func SetAccountCapabilities(capabilities config.AccountCapabilities) error {
	key := identityKey.PrivateKey.Key()[:]
	unidentifiedAccessKey, err := unidentifiedAccess.DeriveAccessKeyFrom(key)
	if err != nil {
		log.Errorln("[textsecure] SetAccountCapabilities ceating unidentifiedAccessKey: ", err)
		return err
	}
	attributes := UpdateAccountAttributes{
		SignalingKey:                   nil,
		RegistrationID:                 registration.Registration.RegistrationID,
		FetchesMessages:                true,
		Pin:                            nil,
		Name:                           config.ConfigFile.Name,
		RegistrationLock:               nil,
		UnidentifiedAccessKey:          &unidentifiedAccessKey,
		UnrestrictedUnidentifiedAccess: true,
		Capabilities:                   capabilities,
		DiscoverableByPhoneNumber:      true,
		Video:                          false,
		Voice:                          false,
	}

	err = setAccountAttributes(&attributes)
	if err != nil {
		return err
	}
	return nil
}

// SetAccountAttributes updates the account attributes
func setAccountAttributes(attributes *UpdateAccountAttributes) error {
	log.Debugln("[textsecure] setAccountAttributes")
	body, err := json.Marshal(attributes)
	if err != nil {
		return err
	}
	resp, err := transport.Transport.PutJSON(SET_ACCOUNT_ATTRIBUTES, body)
	if err != nil {
		return err
	}
	if resp.IsError() {
		return resp
	}
	return nil
}

type whoAmIResponse struct {
	UUID string `json:"uuid"`
}

// GetMyUUID returns the uid from the current user
func GetMyUUID() (string, error) {
	log.Debugln("[textsecure] get my uuid")
	resp, err := transport.Transport.Get(WHO_AM_I)
	if err != nil {
		return "", err
	}
	if resp.IsError() {
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
	resp, err := transport.Transport.Get(provisioningCodePath)
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

	resp, err := transport.Transport.Get(fmt.Sprintf(devicePath, ""))
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
	_, err := transport.Transport.Del(fmt.Sprintf(devicePath, strconv.Itoa(id)))
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
		Uuid:               &config.ConfigFile.UUID,
		ProvisioningCode:   &verificationCode,
		Number:             &config.ConfigFile.Tel,
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
	resp, err := transport.Transport.PutJSON(url, body)
	if err != nil {
		return err
	}
	if resp.IsError() {
		return resp
	}
	return nil
}

type RemoteAttestationRequest struct {
	ClientPublic string
}

// {"clientPublic":"DtZ1bEvFbDPgueDL30P3gh34GLeDAWCSIIXRECU7TCk="}
type Envelopes map[string]DiscoveryContact

type ContactDiscoveryRequest struct {
	AdressCount int
	Commitment  string
	Data        string
	Iv          string
	Mac         string
	Envelopes   Envelopes
}
type DiscoveryContact struct {
	Data      string
	Iv        string
	Mac       string
	RequestId string
}

// SyncContacts syncs the contacts
func SyncContacts() error {
	var t signalservice.SyncMessage_Request_Type
	t = signalservice.SyncMessage_Request_CONTACTS
	omsg := &signalservice.SyncMessage{
		Request: &signalservice.SyncMessage_Request{
			Type: &t,
		},
	}
	_, err := sendSyncMessage(omsg, nil)
	if err != nil {
		return err
	}

	return nil
}

// PUT /v2/keys/
func registerPreKeys() error {
	body, err := json.MarshalIndent(preKeys, "", "")
	if err != nil {
		return err
	}

	resp, err := transport.Transport.PutJSON(prekeyMetadataPath, body)
	if err != nil {
		return err
	}
	if resp.IsError() {
		return resp
	}
	return nil
}

// GET /v2/keys/{number}/{device_id}?relay={relay}
func getPreKeys(UUID string, deviceID string) (*preKeyResponse, error) {
	log.Debugln("getPreKeys", UUID, deviceID)
	resp, err := transport.Transport.Get(fmt.Sprintf(prekeyDevicePath, UUID, deviceID))
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		return nil, resp
	}
	dec := json.NewDecoder(resp.Body)
	k := &preKeyResponse{}
	dec.Decode(k)

	return k, nil
}

func getContactDiscoveryRegisteredUsers(authorization string, request *contactDiscoveryCrypto.DiscoveryRequest, cookies string, mrenclave string) (*contactDiscoveryCrypto.DiscoveryResponse, error) {
	log.Debugln("[textsecure] getContactDiscoveryRegisteredUser")
	body, err := json.Marshal(*request)

	if err != nil {
		return nil, err
	}
	resp, err := transport.DirectoryTransport.PutJSONWithAuthCookies(
		fmt.Sprintf(CONTACT_DISCOVERY, mrenclave),
		body,
		authorization,
		cookies,
	)
	if err != nil {
		return nil, err
	}
	discoveryResponse := &contactDiscoveryCrypto.DiscoveryResponse{}
	dec := json.NewDecoder(resp.Body)
	log.Debugln("[textsecure] GetAndVerifyMultiRemoteAttestation resp")
	err = dec.Decode(&discoveryResponse)
	if err != nil {
		return nil, err
	}
	return discoveryResponse, nil
	// return nil, fmt.Errorf("fail")
}
func idToHexUUID(id []byte) string {
	msb := id[:8]
	lsb := id[8:]
	msbHex := hex.EncodeToString(msb)
	lsbHex := hex.EncodeToString(lsb)
	return msbHex[:8] + "-" + msbHex[8:12] + "-" + msbHex[12:] + "-" + lsbHex[:4] + "-" + lsbHex[4:]
}

// GetRegisteredContacts returns the subset of the local contacts
// that are also registered with the server
func GetRegisteredContacts() ([]contacts.Contact, error) {
	log.Debugln("[textsecure] GetRegisteredContacts")

	lc, err := client.GetLocalContacts()
	if err != nil {
		return nil, fmt.Errorf("could not get local contacts :%s", err)
	}
	tokensMap := map[string]*string{}
	tokens := []string{}
	m := []contacts.Contact{}
	// todo deduplicate contacts
	for _, c := range lc {
		t := c.Tel
		if tokensMap[t] == nil {
			m = append(m, c)
			tokens = append(tokens, t)
			tokensMap[t] = &t
		}

	}

	authCredentials, err := transport.GetCredendtails(DIRECTORY_AUTH_PATH)
	if err != nil {
		return nil, fmt.Errorf("could not get auth credentials %v", err)
	}
	remoteAttestation := contactsDiscovery.RemoteAttestation{}
	attestations, err := remoteAttestation.GetAndVerifyMultiRemoteAttestation(CDS_MRENCLAVE,
		authCredentials.AsBasic(),
	)
	if err != nil {
		return nil, fmt.Errorf("could not get remote attestation %v", err)
	}
	log.Debugln("[textsecure] GetRegisteredContacts assestations")
	request, err := contactDiscoveryCrypto.CreateDiscoveryRequest(tokens, attestations)
	if err != nil {
		return nil, fmt.Errorf("could not get create createDiscoveryRequest %v", err)
	}
	log.Debugln("[textsecure] GetRegisteredContacts contactDiscoveryRequest")

	response, err := getContactDiscoveryRegisteredUsers(authCredentials.AsBasic(), request, remoteAttestation.Cookies, CDS_MRENCLAVE)
	if err != nil {
		return nil, fmt.Errorf("could not get get ContactDiscovery %v", err)
	}

	responseData, err := contactDiscoveryCrypto.GetDiscoveryResponseData(*response, attestations)
	if err != nil {
		return nil, fmt.Errorf("could not get get ContactDiscovery data %v", err)
	}
	uuidlength := 16
	ind := 0

	for i := range m {
		m[i].UUID = idToHexUUID(responseData[ind*uuidlength : (ind+1)*uuidlength])
		ind++
	}
	lc = []contacts.Contact{}
	contacts.Contacts = map[string]contacts.Contact{}
	for _, c := range m {
		lc = append(lc, c)

		if c.UUID != "" && c.UUID != "0" && (c.UUID[0] != 0 || c.UUID[len(c.UUID)-1] != 0) {
			contacts.Contacts[c.UUID] = c

		} else {
			contacts.Contacts[c.Tel] = c
			log.Debugln("[textsecure] empty uuid for tel ", c.Tel)
		}
	}
	err = contacts.WriteContactsToPath()
	if err != nil {
		log.Debugln("[textsecure] 3", err)

	}
	return lc, nil
}

// Attachment handling

type jsonAllocation struct {
	ID       uint64 `json:"id"`
	Location string `json:"location"`
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
	dm.ProfileKey = config.ConfigFile.ProfileKey
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

func buildMessage(reciever string, paddedMessage []byte, devices []uint32, isSync bool) ([]jsonMessage, error) {
	if len(reciever) == 0 {
		return nil, fmt.Errorf("empty reciever")
	}
	recid, err := recID(reciever)
	if err != nil {
		return nil, err
	}
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
	// unidentifiedAccessKeyPair, err := unidentifiedAccess.GetAccessForUUID(contacts.GetContact(uuid))
	if err != nil {
		return nil, err
	}
	resp, err := transport.Transport.PutJSON(fmt.Sprintf(MESSAGE_PATH, uuid), body)
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
			uuidCleanup, err := recID(uuid)
			if err != nil {
				return nil, err
			}
			textSecureStore.DeleteSession(uuidCleanup, id)
		}
		return buildAndSendMessage(uuid, paddedMessage, isSync, timestamp)
	}
	if resp.IsError() {
		return nil, resp
	}

	var smRes sendMessageResponse
	dec := json.NewDecoder(resp.Body)
	dec.Decode(&smRes)
	smRes.Timestamp = *timestamp

	log.Debugf("[textsecure] SendMessageResponse: %+v\n", smRes)
	return &smRes, nil
}
