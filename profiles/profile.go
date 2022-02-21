package profiles

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"

	zkgroup "github.com/nanu-c/zkgroup"
	uuidUtil "github.com/satori/go.uuid"
	"github.com/signal-golang/textsecure/config"
	"github.com/signal-golang/textsecure/contacts"
	"github.com/signal-golang/textsecure/crypto"
	"github.com/signal-golang/textsecure/transport"
	log "github.com/sirupsen/logrus"
)

const (
	PROFILE_PATH            = "/v1/profile/%s"
	PROFILE_CREDENTIAL_PATH = "/v1/profile/%s/%s/%s"
	NAME_PADDED_LENGTH      = 53
)

// Profile ...
type ProfileSettings struct {
	Version        string   `json:"version"`
	Name           []byte   `json:"name"`
	About          []byte   `json:"about"`
	AboutEmoji     []byte   `json:"aboutEmoji"`
	paymentAddress []byte   `json:"paymentAddress"`
	Avatar         bool     `json:"avatar"`
	Commitment     []byte   `json:"commitment"`
	BadgeIds       []string `json:"badgeIds"`
}

// GenerateProfileKey generates a new ProfileKey
func GenerateProfileKey() []byte {
	profileKey := make([]byte, 32)
	rand.Read(profileKey)
	return profileKey
}
func uuidToByte(id string) []byte {
	s, _ := uuidUtil.FromString(id)
	return s.Bytes()
}

// UpdateProfile ...
func UpdateProfile(profileKey []byte, uuid, name string) error {
	log.Debugln("[textsecure] UpdateProfile", uuid, name)
	uuidByte := uuidToByte(uuid)

	profile := ProfileSettings{}
	version, err := zkgroup.ProfileKeyGetProfileKeyVersion(profileKey, uuidByte)
	if err != nil {
		return err
	}
	commitment, err := zkgroup.ProfileKeyGetCommitment(profileKey, uuidByte)
	if err != nil {
		return err
	}
	nameCiphertext, err := encryptName(profileKey, []byte(name), NAME_PADDED_LENGTH)
	if err != nil {
		return err
	}
	profile.Version = string(version[:])
	profile.Commitment = commitment
	profile.Name = nameCiphertext
	profile.Avatar = false
	err = writeOwnProfile(profile)
	if err != nil {
		return err
	}
	myProfile, err := GetProfile(uuid, profileKey)
	if err != nil {
		return err
	}
	config.ConfigFile.AccountCapabilities = myProfile.Capabilities
	return nil
}

// WriteProfile ...
func writeOwnProfile(profile ProfileSettings) error {
	body, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	transport.Transport.PutJSON(fmt.Sprintf(PROFILE_PATH, ""), body)
	return nil
}

func encryptName(key, input []byte, paddedLength int) ([]byte, error) {
	inputLength := len(input)
	if inputLength > paddedLength {
		return nil, errors.New("Input too long")
	}
	padded := append(input, make([]byte, paddedLength-inputLength)...)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	ciphertext, err := crypto.AesgcmEncrypt(key, nonce, padded)
	if err != nil {
		return nil, err
	}
	return append(nonce, ciphertext...), nil
}

func decryptName(key, nonceAndCiphertext []byte) ([]byte, error) {
	if len(nonceAndCiphertext) < 12+16+1 {
		return nil, errors.New("nonceAndCipher too short")
	}
	nonce := nonceAndCiphertext[:12]
	ciphertext := nonceAndCiphertext[12:]
	padded, err := crypto.AesgcmDecrypt(key, nonce, ciphertext, []byte{})
	if err != nil {
		return nil, err
	}
	paddedLength := len(padded)
	plaintextLength := 0
	for i := paddedLength - 1; i >= 0; i-- {
		if padded[i] != byte(0) {
			plaintextLength = i + 1
			break
		}
	}
	return padded[:plaintextLength], nil
}

func getCommitment(profileKey, uuid []byte) ([]byte, error) {
	return zkgroup.ProfileKeyGetCommitment(profileKey, uuid)
}

// Profile describes the profile type
type Profile struct {
	IdentityKey                    string                     `json:"identityKey"`
	UnidentifiedAccess             string                     `json:"unidentifiedAccess"`
	UnrestrictedUnidentifiedAccess bool                       `json:"unrestrictedUnidentifiedAccess"`
	Capabilities                   config.AccountCapabilities `json:"capabilities"`
	Badges                         []string                   `json:"badges"`
	UUID                           string                     `json:"uuid"`
	Name                           string                     `json:"name"`
	About                          string                     `json:"about"`
	AboutEmoji                     string                     `json:"aboutEmoji"`
	Avatar                         string                     `json:"avatar"`
	PaymentAddress                 string                     `json:"paymentAddress"`
	Credential                     []byte                     `json:"credential"`
}

func GetProfile(UUID string, profileKey []byte) (*Profile, error) {
	resp, err := transport.Transport.Get(fmt.Sprintf(PROFILE_PATH, UUID))
	profile := &Profile{}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&profile)
	if err != nil {
		log.Debugln("[textsecure] GetProfile", err)
		return nil, err
	} else {
		err = decryptProfile(profileKey, profile)
		if err != nil {
			log.Debugln("[textsecure] ", err)
			return nil, err
		}
	}
	return profile, nil

}
func GetProfileAndCredential(UUID string, profileKey []byte) (*Profile, error) {
	log.Infoln("[textsecure] GetProfileAndCredential")
	uuid, err := uuidUtil.FromString(UUID)
	if err != nil {
		log.Debugln("[textsecure] GetProfileAndCredential", err)
		return nil, err
	}
	zkGroupServerPublicParams, _ := base64.StdEncoding.DecodeString(config.ZKGROUP_SERVER_PUBLIC_PARAMS)

	requestContext, err := zkgroup.CreateProfileKeyCredentialRequestContext(zkGroupServerPublicParams, uuid.Bytes(), profileKey)
	if err != nil {
		log.Debugln("[textsecure] createProfileCredentialRequest", err)
		return nil, err
	}
	credentialsRequest, err := requestContext.ProfileKeyCredentialRequestContextGetRequest()
	if err != nil {
		log.Debugln("[textsecure] GetProfileAndCredential", err)
		return nil, err
	}
	credentialsRequestHex := hex.EncodeToString(credentialsRequest)

	version, err := zkgroup.ProfileKeyGetProfileKeyVersion(profileKey, uuid.Bytes())
	if err != nil {
		log.Debugln("[textsecure] GetProfileAndCredential", err)
		return nil, err
	}
	resp, err := transport.Transport.Get(fmt.Sprintf(PROFILE_CREDENTIAL_PATH, UUID, version, credentialsRequestHex))
	if err != nil {
		log.Debugln("[textsecure] GetProfileAndCredential", err)
		return nil, err
	}
	profile := &Profile{}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&profile)
	if err != nil {
		log.Debugln("[textsecure] GetProfileAndCredential", err)
		return nil, err
	} else {
		err = decryptProfile(profileKey, profile)
		if err != nil {
			log.Debugln("[textsecure] GetProfileAndCredential", err)
			return nil, err
		}
	}
	response := zkgroup.ProfileKeyCredentialResponse(profile.Credential)
	if err != nil {
		log.Debugln("[textsecure] GetProfileAndCredential", err)
		return nil, err
	}
	serverPublicParams, err := zkgroup.NewServerPublicParams(zkGroupServerPublicParams)
	if err != nil {
		log.Debugln("[textsecure] GetProfileAndCredential", err)
		return nil, err
	}
	credential, err := serverPublicParams.ReceiveProfileKeyCredential(requestContext, response)
	if err != nil {
		log.Debugln("[textsecure] GetProfileAndCredential", err)
		return nil, err
	}
	log.Debugln("[textsecure] GetProfileAndCredential", len(credential))
	profile.Credential = credential

	return profile, err

}
func decryptProfile(profileKey []byte, profile *Profile) error {
	log.Println("[textsecure] decryptProfile")
	name, err := decryptString(profileKey, profile.Name)
	if err != nil {
		log.Debugln("[textsecure] decryptProfile name", err)
		return err
	}
	profile.Name = name
	if profile.About != "" {
		about, err := decryptString(profileKey, profile.About)
		if err != nil {
			log.Debugln("[textsecure] decryptProfile about", err)
			return err
		}
		profile.About = about
	}
	if profile.AboutEmoji != "" {

		emoji, err := decryptString(profileKey, profile.AboutEmoji)
		if err != nil {
			log.Debugln("[textsecure] decryptProfile aboutEmoji", err)
			return err
		}
		profile.AboutEmoji = emoji
	}
	identityKey, err := base64.StdEncoding.DecodeString(profile.IdentityKey)
	if err != nil {
		log.Debugln("[textsecure] decryptProfile identitykey", err)
		return err
	}
	profile.IdentityKey = string(identityKey)

	return nil
}

func decryptString(profileKey []byte, data string) (string, error) {
	bData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	dData, err := decryptName(profileKey, bData)
	if err != nil {
		return "", err
	}
	return string(dData), nil

}
func createProfileCredentialRequest(uuid, profileKey []byte) (zkgroup.ProfileKeyCredentialRequest, error) {
	zkGroupServerPublicParams, _ := base64.StdEncoding.DecodeString(config.ZKGROUP_SERVER_PUBLIC_PARAMS)

	requestContext, err := zkgroup.CreateProfileKeyCredentialRequestContext(zkGroupServerPublicParams, uuid, profileKey)
	if err != nil {
		log.Debugln("[textsecure] createProfileCredentialRequest", err)
		return nil, err
	}
	return requestContext.ProfileKeyCredentialRequestContextGetRequest()
}

// GetProfileE164 get a profile by a phone number
func GetProfileE164(tel string) (contacts.Contact, error) {

	resp, err := transport.Transport.Get(fmt.Sprintf(PROFILE_PATH, tel))
	if err != nil {
		log.Errorln("[textsecure] GetProfileE164 ", err)
	}

	profile := &Profile{}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&profile)
	if err != nil {
		log.Errorln("[textsecure] GetProfileE164 ", err)
	}
	avatar, _ := GetAvatar(profile.Avatar)
	buf := new(bytes.Buffer)
	buf.ReadFrom(avatar)

	c := contacts.Contacts[profile.UUID]
	avatarDecrypted, err := decryptAvatar(buf.Bytes(), []byte(profile.IdentityKey))
	if err != nil {
		log.Errorln("[textsecure] GetProfileE164 ", err)
	}
	c.Name = profile.Name
	c.UUID = profile.UUID
	c.HasAvatar = true
	c.AvatarImg = avatarDecrypted
	contacts.Contacts[c.UUID] = c
	contacts.WriteContactsToPath()
	return c, nil
}
