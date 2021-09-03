package unidentifiedAccess

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/signal-golang/textsecure/config"
	"github.com/signal-golang/textsecure/contacts"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	log "github.com/sirupsen/logrus"
)

func DeriveAccessKeyFrom(profileKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(profileKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	input := make([]byte, 16)

	ciphertext := aesgcm.Seal(nil, nonce, input, nil)
	return ciphertext[:16], nil
}

var ErrCertificateEmpty = errors.New("certificate is empty")

func CheckCertificate(certificate []byte) error {
	log.Infoln("[textsecure] Checking certificate")

	if len(certificate) == 0 {
		return ErrCertificateEmpty
	}
	serverCert := &signalservice.ServerCertificate{}
	if err := proto.Unmarshal(certificate, serverCert); err != nil {
		log.Fatalln("Failed to parse certificate:", err)
		return err
	}
	senderCertificate := &signalservice.SenderCertificate_Certificate{}
	if err := proto.Unmarshal(serverCert.Certificate, senderCertificate); err != nil {
		log.Fatalln("Failed to parse sender certificate:", err)
		return err
	}
	fmt.Printf("sendercert %+v\n", senderCertificate)
	if *senderCertificate.Expires < uint64(time.Now().Unix()) {
		log.Errorln("Certificate expired")
		return errors.New("certificate expired")
	}
	return nil
}

type UnidentifiedAccess struct {
	UnidentifiedAccessKey   []byte `json:"unidentifiedAccessKey"`
	UnidentifiedCertificate []byte `json:"unidentifiedCertificate"`
}
type UnidentifiedAccessPair struct {
	TargetUnidentifiedAccess UnidentifiedAccess `json:"targetUnidentifiedAccess"`
	SelfUnidentifiedAccess   UnidentifiedAccess `json:"selfUnidentifiedAccess"`
}

func GetAccessForSync(profileKey []byte, cert []byte) (*UnidentifiedAccess, error) {
	log.Infoln("[textsecure] Getting access key for sync")
	unidentifiedAccessKey, err := DeriveAccessKeyFrom(profileKey)
	if err != nil {
		return nil, err
	}
	return &UnidentifiedAccess{
		UnidentifiedAccessKey:   unidentifiedAccessKey,
		UnidentifiedCertificate: cert,
	}, nil
}
func GetTargetUnidentifiedAccessKey(contact contacts.Contact) ([]byte, error) {
	log.Infoln("[textsecure] Getting target unidentified access key")
	if contact.ProfileKey != nil {
		return DeriveAccessKeyFrom(contact.ProfileKey)
	} else {
		token := make([]byte, 16)
		rand.Read(token)
		return token, nil
	}
}

func GetAccessFor(recipents []contacts.Contact) (*[]UnidentifiedAccessPair, error) {
	log.Infoln("[textsecure] Getting access key for")
	// todo: check for isUniversalUnidentifiedAccess
	ourUnidentifiedAccessKey, err := DeriveAccessKeyFrom(config.ConfigFile.ProfileKey)
	if err != nil {
		return nil, err
	}
	ourCertificate, err := GetOurCertificate()
	if err != nil {
		return nil, err
	}
	var unidentifiedAccessPairs []UnidentifiedAccessPair
	for _, contact := range recipents {
		theirUnidentifiedAccessKey, err := GetTargetUnidentifiedAccessKey(contact)
		if err != nil {
			return nil, err
		}

		unidentifiedAccessPairs = append(unidentifiedAccessPairs, UnidentifiedAccessPair{
			TargetUnidentifiedAccess: UnidentifiedAccess{
				UnidentifiedAccessKey:   theirUnidentifiedAccessKey,
				UnidentifiedCertificate: ourCertificate,
			},
			SelfUnidentifiedAccess: UnidentifiedAccess{
				UnidentifiedAccessKey:   ourUnidentifiedAccessKey,
				UnidentifiedCertificate: ourCertificate,
			},
		})
	}
	return &unidentifiedAccessPairs, nil
}
func GetAccessForUUID(recipent contacts.Contact) (*UnidentifiedAccessPair, error) {
	log.Infoln("[textsecure] Getting access key for")
	// todo: check for isUniversalUnidentifiedAccess
	ourUnidentifiedAccessKey, err := DeriveAccessKeyFrom(config.ConfigFile.ProfileKey)
	if err != nil {
		return nil, err
	}
	ourCertificate, err := GetOurCertificate()
	if err != nil {
		return nil, err
	}
	theirUnidentifiedAccessKey, err := GetTargetUnidentifiedAccessKey(recipent)

	return &UnidentifiedAccessPair{
		TargetUnidentifiedAccess: UnidentifiedAccess{
			UnidentifiedAccessKey:   theirUnidentifiedAccessKey,
			UnidentifiedCertificate: ourCertificate,
		},
		SelfUnidentifiedAccess: UnidentifiedAccess{
			UnidentifiedAccessKey:   ourUnidentifiedAccessKey,
			UnidentifiedCertificate: ourCertificate,
		},
	}, nil
}
func GetOurCertificate() ([]byte, error) {
	log.Infoln("[textsecure] Getting our certificate")
	cert := &signalservice.ServerCertificate{}
	if err := proto.Unmarshal(config.ConfigFile.Certificate, cert); err != nil {
		log.Fatalln("Failed to parse certificate:", err)
		return nil, err
	}
	return cert.Certificate, nil
}

func (u *UnidentifiedAccess) GetTargetUnidentifiedAccess(contact contacts.Contact) (*UnidentifiedAccessPair, error) {
	log.Infoln("[textsecure] Getting target unidentified access")

	theirProfileKey := contact.GetProfileKey()
	// TODO: Get unidentified access mode
	accessKey, err := DeriveAccessKeyFrom(theirProfileKey)
	if err != nil {
		return nil, err
	}
	cert, err := GetOurCertificate()
	if err != nil {
		return nil, err
	}
	return &UnidentifiedAccessPair{
		SelfUnidentifiedAccess: *u,
		TargetUnidentifiedAccess: UnidentifiedAccess{
			UnidentifiedAccessKey:   accessKey,
			UnidentifiedCertificate: cert,
		},
	}, nil

}

func (uap *UnidentifiedAccessPair) GetTargetKey() []byte {
	return uap.TargetUnidentifiedAccess.UnidentifiedAccessKey
}
