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
	"strings"

	signalservice "github.com/signal-golang/textsecure/protobuf"
	textsecure "github.com/signal-golang/textsecure/protobuf"
	"github.com/signal-golang/textsecure/transport"
	log "github.com/sirupsen/logrus"
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

// putAttachment uploads an encrypted attachment to the given relative URL using the CdnTransport
func putAttachmentV3(url string, body []byte) ([]byte, error) {
	response, err := transport.CdnTransport.Put(url, body, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	if response.IsError() {
		return nil, response
	}
	hasher := sha256.New()
	hasher.Write(body)

	return hasher.Sum(nil), nil
}

// uploadAttachment encrypts, authenticates and uploads a given attachment to a location requested from the server
func uploadAttachment(r io.Reader, ct string) (*attachmentPointerV3, error) {
	return uploadAttachmentV3(r, ct, false)
}

// uploadAttachmentV3 encrypts, authenticates and uploads a given attachment to a location requested from the server
func uploadAttachmentV3(r io.Reader, ct string, isVoiceNote bool) (*attachmentPointerV3, error) {
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

	location, uploadAttributes, err := allocateAttachmentV3()
	if err != nil {
		return nil, err
	}
	digest, err := putAttachmentV3(location, m)
	if err != nil {
		return nil, err
	}
	return &attachmentPointerV3{uploadAttributes.Key, uploadAttributes.Cdn, ct, keys, digest, uint32(plaintextLength), isVoiceNote}, nil
}

func uploadVoiceNote(r io.Reader, ct string) (*attachmentPointerV3, error) {
	return uploadAttachmentV3(r, "audio/mpeg", true)
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

func getAttachmentV3UploadAttributes() (*attachmentV3UploadAttributes, error) {
	resp, err := transport.ServiceTransport.Get(ATTACHMENT_V3_PATH)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(resp.Body)
	var a attachmentV3UploadAttributes
	err = dec.Decode(&a)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func relativePath(url string) string {
	parts := strings.Split(url, "/")
	return "/" + strings.Join(parts[3:], "/")
}

func (a *attachmentV3UploadAttributes) relativeSignedUploadLocation() string {
	return relativePath(a.SignedUploadLocation)
}

func allocateAttachmentV3() (string, *attachmentV3UploadAttributes, error) {
	uploadAttributes, err := getAttachmentV3UploadAttributes()
	if err != nil {
		return "", nil, err
	}
	resp, err := transport.CdnTransport.PostWithHeaders(
		uploadAttributes.relativeSignedUploadLocation(),
		[]byte{},
		"application/octet-stream",
		uploadAttributes.Headers)
	if err != nil {
		return "", nil, err
	}
	if resp.IsError() {
		log.Debug("[textsecure] allocateAttachmentV3 error response ", resp.Body)
		return "", nil, resp
	}
	location := resp.Header.Get("Location")
	return relativePath(location), uploadAttributes, nil
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
