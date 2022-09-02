// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	signalservice "github.com/signal-golang/textsecure/protobuf"
	textsecure "github.com/signal-golang/textsecure/protobuf"
	"github.com/signal-golang/textsecure/transport"
)

// getAttachment downloads an encrypted attachment blob from the given URL
func getAttachment(url string) (io.ReadCloser, error) {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	c := &http.Client{Transport: customTransport}
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Host", SERVICE_REFLECTOR_HOST)
	req.Header.Add("Content-Type", "application/octet-stream")

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}

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
func uploadAttachment(r io.Reader, ct string) (*att, error) {
	//combined AES-256 and HMAC-SHA256 key
	keys := make([]byte, 64)
	randBytes(keys)

	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	plaintextLength := len(b)

	e, err := aesEncrypt(keys[:32], b)
	if err != nil {
		return nil, err
	}

	m := appendMAC(keys[32:], e)

	id, location, err := allocateAttachment()
	if err != nil {
		return nil, err
	}
	digest, err := putAttachment(location, m)
	if err != nil {
		return nil, err
	}

	return &att{id, ct, keys, digest, uint32(plaintextLength), false}, nil
}
func uploadVoiceNote(r io.Reader, ct string) (*att, error) {
	ct = "audio/mpeg"
	//combined AES-256 and HMAC-SHA256 key
	keys := make([]byte, 64)
	randBytes(keys)

	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	plaintextLength := len(b)

	e, err := aesEncrypt(keys[:32], b)
	if err != nil {
		return nil, err
	}

	m := appendMAC(keys[32:], e)

	id, location, err := allocateAttachment()
	if err != nil {
		return nil, err
	}
	digest, err := putAttachment(location, m)
	if err != nil {
		return nil, err
	}

	return &att{id, ct, keys, digest, uint32(plaintextLength), true}, nil
}

// ErrInvalidMACForAttachment signals that the downloaded attachment has an invalid MAC.
var ErrInvalidMACForAttachment = errors.New("invalid MAC for attachment")

func handleSingleAttachment(a *textsecure.AttachmentPointer) (*Attachment, error) {
	loc, err := getAttachmentLocation(a.GetCdnId(), a.GetCdnKey(), a.GetCdnNumber())
	if err != nil {
		return nil, err
	}
	r, err := getAttachment(loc)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	l := len(b) - 32
	if !verifyMAC(a.Key[32:], b[:l], b[l:]) {
		return nil, ErrInvalidMACForAttachment
	}

	b, err = aesDecrypt(a.Key[:32], b[:l])
	if err != nil {
		return nil, err
	}

	// TODO: verify digest

	return &Attachment{bytes.NewReader(b), a.GetContentType(), a.GetFileName()}, nil
}
func handleProfileAvatar(profileAvatar *signalservice.ContactDetails_Avatar, key []byte) (*Attachment, error) {

	loc, err := getProfileLocation(profileAvatar.String())
	if err != nil {
		return nil, err
	}
	r, err := getAttachment(loc)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	l := len(b) - 16
	if !verifyMAC(key[16:], b[:l], b[l:]) {
		return nil, ErrInvalidMACForAttachment
	}

	b, err = aesDecrypt(key[:16], b[:l])
	if err != nil {
		return nil, err
	}

	// TODO: verify digest

	return &Attachment{bytes.NewReader(b), profileAvatar.GetContentType(), ""}, nil
}

func handleAttachments(dm *textsecure.DataMessage) ([]*Attachment, error) {
	atts := dm.GetAttachments()
	if atts == nil {
		return nil, nil
	}

	all := make([]*Attachment, len(atts))
	var err error
	for i, a := range atts {
		all[i], err = handleSingleAttachment(a)
		if err != nil {
			return nil, err
		}
	}
	return all, nil
}

// GET /v1/attachments/
func allocateAttachment() (uint64, string, error) {
	resp, err := transport.Transport.Get(allocateAttachmentPath)
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
