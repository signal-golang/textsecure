package profiles

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	siv "github.com/Blackoverflow/gcmsiv"
	"github.com/signal-golang/textsecure/config"
	transport "github.com/signal-golang/textsecure/transport"

	"crypto/aes"
	"crypto/cipher"

	log "github.com/sirupsen/logrus"
)

const NONCE_LEN = 12

var (
	avatarsPath string
)

// GetAvatar returns an avatar for it's url from signal cdn
func GetRemoteAvatar(avatarURL string) (io.ReadCloser, error) {
	log.Debugln("[textsecure] get avatar from ", avatarURL)
	if avatarURL == "" {
		return nil, fmt.Errorf("empty avatar url")
	}
	resp, err := transport.CdnTransport.Get(avatarURL)
	if err != nil {
		log.Debugln("[textsecure] getAvatar ", err)

		return nil, err
	}

	return resp.Body, nil
}
func GetLocalAvatarPath(uuid string) (string, error) {
	log.Debugln("[textsecure] get local avatar for ", uuid)
	if uuid == "" {
		return "", fmt.Errorf("empty uuid")
	}
	if avatarsPath == "" {
		err := setupAvatarsPath()
		if err != nil {
			return "", err
		}
	}
	avatarFile := filepath.Join(avatarsPath, uuid)
	return avatarFile, nil
}
func GetLocalAvatar(uuid string) (io.ReadCloser, error) {
	log.Debugln("[textsecure] get local avatar for ", uuid)
	if uuid == "" {
		return nil, fmt.Errorf("empty uuid")
	}
	if avatarsPath == "" {
		err := setupAvatarsPath()
		if err != nil {
			return nil, err
		}
	}
	avatarFile := filepath.Join(avatarsPath, uuid)
	f, err := os.Open(avatarFile)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func SaveAvatar(uuid string, avatar []byte) error {
	err := saveLocalAvatar(uuid, avatar)
	if err != nil {
		log.Errorln("[textsecure] failed to save avatar ", err)
		return err
	}
	return nil
}

func saveLocalAvatar(uuid string, avatar []byte) error {
	log.Debugln("[textsecure] save local avatar for ", uuid)
	if uuid == "" {
		return fmt.Errorf("empty uuid")
	}
	if len(avatar) == 0 {
		return fmt.Errorf("empty avatar")
	}
	if avatarsPath == "" {
		err := setupAvatarsPath()
		if err != nil {
			return err
		}
	}
	avatarFile := filepath.Join(avatarsPath, uuid)
	log.Debugln("[textsecure] save avatar to ", avatarFile)
	f, err := os.Create(avatarFile)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(avatar)
	if err != nil {
		return err
	}
	log.Debugln("[textsecure] saved avatar for ", uuid)
	return nil
}

func setupAvatarsPath() error {

	avatarsPath = filepath.Join(config.ConfigFile.StorageDir, "avatars")
	if err := os.MkdirAll(avatarsPath, 0700); err != nil {
		return err
	}
	return nil
}

func decryptAvatar(avatar []byte, identityKey []byte) ([]byte, error) {
	nonce := avatar[:NONCE_LEN]
	encrypted_avatar := avatar[NONCE_LEN:]
	decryptedAvatar, err := decrypt(identityKey[:32], encrypted_avatar, nonce)
	if err != nil {
		log.Debugln("[textsecure] failed to decrypt Avatar ", err)
		return nil, err
	}
	return decryptedAvatar, nil
}

func decrypt(key, data, nonce []byte) ([]byte, error) {
	// aessiv, err := siv.NewGCMSIV(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err

	}
	plaintext, err := aesgcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err

	}
	return plaintext, nil
}

func encrypt(key, data, nonce []byte) ([]byte, error) {
	aessiv, err := siv.NewGCMSIV(key)
	if err != nil {
		return nil, err
	}

	encrypted := aessiv.Seal(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}
