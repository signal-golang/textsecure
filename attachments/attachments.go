// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package attachments

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"

	siv "github.com/blackoverflow/gcmsiv"
	"github.com/signal-golang/textsecure/config"
	"github.com/signal-golang/textsecure/crypto"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	textsecure "github.com/signal-golang/textsecure/protobuf"
	"github.com/signal-golang/textsecure/transport"
	log "github.com/sirupsen/logrus"
)

const NONCE_LEN = 12

// Attachment represents an attachment received from a peer
type Attachment struct {
	R        io.Reader
	MimeType string
	FileName string
}

type Att struct {
	Id        uint64
	Ct        string
	Keys      []byte
	Digest    []byte
	Size      uint32
	VoiceNote bool
}
type jsonAllocation struct {
	ID       uint64 `json:"id"`
	Location string `json:"location"`
}

// getAttachment downloads an encrypted attachment blob from the given URL
func getAttachment(url string) (io.ReadCloser, error) {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	c := &http.Client{Transport: customTransport}
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Host", config.SERVICE_REFLECTOR_HOST)
	req.Header.Add("Content-Type", "application/octet-stream")

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	log.Debugln("[textsecure] get attachment:", url, resp.StatusCode)

	return resp.Body, nil
}

// putAttachment uploads an encrypted attachment to the given URL
func putAttachment(url string, body []byte) ([]byte, error) {
	br := bytes.NewReader(body)
	req, err := http.NewRequest("PUT", url, br)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/octet-stream")
	req.Header.Add("Content-Length", strconv.Itoa(len(body)))

	client := transport.NewHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP status %d\n", resp.StatusCode)
	}

	hasher := sha256.New()
	hasher.Write(body)

	return hasher.Sum(nil), nil
}

// uploadAttachment encrypts, authenticates and uploads a given attachment to a location requested from the server
func UploadAttachment(r io.Reader, ct string) (*Att, error) {
	//combined AES-256 and HMAC-SHA256 key
	keys := make([]byte, 64)
	crypto.RandBytes(keys)

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	plaintextLength := len(b)

	e, err := crypto.AesEncrypt(keys[:32], b)
	if err != nil {
		return nil, err
	}

	m := crypto.AppendMAC(keys[32:], e)

	id, location, err := allocateAttachment()
	if err != nil {
		return nil, err
	}
	digest, err := putAttachment(location, m)
	if err != nil {
		return nil, err
	}

	return &Att{id, ct, keys, digest, uint32(plaintextLength), false}, nil
}
func UploadVoiceNote(r io.Reader, ct string) (*Att, error) {
	ct = "audio/mpeg"
	//combined AES-256 and HMAC-SHA256 key
	keys := make([]byte, 64)
	crypto.RandBytes(keys)

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	plaintextLength := len(b)

	e, err := crypto.AesEncrypt(keys[:32], b)
	if err != nil {
		return nil, err
	}

	m := crypto.AppendMAC(keys[32:], e)

	id, location, err := allocateAttachment()
	if err != nil {
		return nil, err
	}
	digest, err := putAttachment(location, m)
	if err != nil {
		return nil, err
	}

	return &Att{id, ct, keys, digest, uint32(plaintextLength), true}, nil
}

// ErrInvalidMACForAttachment signals that the downloaded attachment has an invalid MAC.
var ErrInvalidMACForAttachment = errors.New("invalid MAC for attachment")

func HandleSingleAttachment(a *textsecure.AttachmentPointer) (*Attachment, error) {
	loc, err := getAttachmentLocation(a.GetCdnId(), a.GetCdnKey(), a.GetCdnNumber())
	if err != nil {
		return nil, err
	}
	r, err := getAttachment(loc)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	l := len(b) - 32
	if !crypto.VerifyMAC(a.Key[32:], b[:l], b[l:]) {
		return nil, ErrInvalidMACForAttachment
	}

	b, err = crypto.AesDecrypt(a.Key[:32], b[:l])
	if err != nil {
		return nil, err
	}

	// TODO: verify digest

	return &Attachment{bytes.NewReader(b), a.GetContentType(), a.GetFileName()}, nil
}
func HandleProfileAvatar(profileAvatar *signalservice.ContactDetails_Avatar, key []byte) (*Attachment, error) {

	path, err := getProfileLocation(profileAvatar.String())
	if err != nil {
		return nil, err
	}
	return GetProfileAvatar(path, key)
}
func GetProfileAvatar(path string, key []byte) (*Attachment, error) {
	if path == "" || len(key) == 0 {
		return nil, errors.New("Invalid path or key")
	}
	log.Debugln("[textsecure] GetProfileAvatar", path)
	loc, err := getProfileLocation(path)
	if err != nil {
		return nil, err
	}
	r, err := getAttachment(loc)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	out, err := decryptAvatar(b, key)
	if err != nil {
		log.Errorln("[textsecure] decryptAvatar error:", err)
	}

	// filetype := http.DetectContentType(out)
	// TODO: verify digest

	return &Attachment{bytes.NewReader(out), "", ""}, nil
}
func getProfileLocation(profilePath string) (string, error) {
	cdn := config.SIGNAL_CDN_URL
	if profilePath[0] == '/' {
		return cdn + fmt.Sprintf(profilePath), nil
	}
	return cdn + "/" + fmt.Sprintf(profilePath), nil

}
func decryptAvatar(avatar []byte, identityKey []byte) ([]byte, error) {
	log.Debugln("[textsecure] decryptAvatar", len(avatar), len(identityKey))
	if len(avatar) == 0 || len(identityKey) == 0 {
		return nil, errors.New("empty avatar or key")
	}
	avatar_len := len(avatar) - NONCE_LEN
	nonce := avatar[avatar_len:]
	encrypted_avatar := avatar[:avatar_len]
	decryptedAvatar, err := decryptAvatarBlob(identityKey[:32], encrypted_avatar, nonce)
	if err != nil {
		return nil, err
	}
	return decryptedAvatar, nil
}

func decryptAvatarBlob(key, data, nonce []byte) ([]byte, error) {
	aessiv, err := siv.NewGCMSIV(key)
	if err != nil {
		log.Debugln("1", err)
		return nil, err
	}
	decrypted, err := aessiv.Open(nil, nonce, data, nil)
	if err != nil {
		log.Debugln("[textsecure] decryptAvatarBlob", err)
		return nil, err
	}
	return decrypted, nil

}

func HandleAttachments(dm *textsecure.DataMessage) ([]*Attachment, error) {
	atts := dm.GetAttachments()
	if atts == nil {
		return nil, nil
	}

	all := make([]*Attachment, len(atts))
	var err error
	for i, a := range atts {
		all[i], err = HandleSingleAttachment(a)
		if err != nil {
			return nil, err
		}
	}
	return all, nil
}

// GET /v1/attachments/
func allocateAttachment() (uint64, string, error) {
	resp, err := transport.Transport.Get(config.AllocateAttachmentPath)
	if err != nil {
		return 0, "", err
	}
	dec := json.NewDecoder(resp.Body)
	var a jsonAllocation
	dec.Decode(&a)
	return a.ID, a.Location, nil
}

func getAttachmentLocation(id uint64, key string, cdnNumber uint32) (string, error) {
	cdn := config.SIGNAL_CDN_URL
	if cdnNumber == 2 {
		cdn = config.SIGNAL_CDN2_URL
	}
	if id != 0 {
		return cdn + fmt.Sprintf(config.ATTACHMENT_ID_DOWNLOAD_PATH, id), nil
	}
	return cdn + fmt.Sprintf(config.ATTACHMENT_KEY_DOWNLOAD_PATH, key), nil
}
