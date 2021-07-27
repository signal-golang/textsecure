package profiles

import (
	"io"

	"github.com/signal-golang/textsecure/crypto"
	transport "github.com/signal-golang/textsecure/transport"
	log "github.com/sirupsen/logrus"
)

// GetAvatar returns an avatar for it's url from signal cdn
func GetAvatar(avatarURL string) (io.ReadCloser, error) {
	log.Debugln("[textsecure] get avatar from ", avatarURL)

	resp, err := transport.CdnTransport.Get(avatarURL)
	if err != nil {
		log.Debugln("[textsecure] getAvatar ", err)

		return nil, err
	}

	return resp.Body, nil
}

func decryptAvatar(avatar []byte, identityKey []byte) ([]byte, error) {

	l := len(avatar[:]) - 30
	b, err := crypto.AesgcmDecrypt(identityKey[:16], avatar[l:], avatar[:l], []byte{})
	if err != nil {
		return nil, err
	}
	return b, nil
}
