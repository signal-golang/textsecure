package crayfish

import (
	b64 "encoding/base64"
	"encoding/json"

	log "github.com/sirupsen/logrus"
)

func (c *CrayfishInstance) DecryptAvatar(avatar, key []byte) ([]byte, error) {
	log.Debugln("[textsecure-crayfish-ws] DecryptAvatar", key)
	messageType := CrayfishWebSocketMessage_REQUEST
	requestType := CrayfishWebSocketRequestMessageTyp_DECRYPT_AVATAR
	sEnc := b64.StdEncoding.EncodeToString(avatar)
	var keyFixedSize [32]byte
	copy(keyFixedSize[:], key)

	envelopeMessage := &CrayfishWebSocketRequest_AVATAR_MESSAGE{
		Avatar: sEnc,
		Key:    keyFixedSize,
	}
	log.Debugln("[textsecure-crayfish-ws] Sending avatar")

	request := &CrayfishWebSocketRequestMessage{
		Type:    &requestType,
		Message: envelopeMessage,
	}
	handleEnvelopeMessage := &CrayfishWebSocketMessage{
		Type:    &messageType,
		Request: request,
	}
	m, err := json.Marshal(handleEnvelopeMessage)
	if err != nil {
		return nil, err
	}
	log.Debugf("[textsecure-crayfish-ws] avatar send")
	c.wsconn.send <- m
	c.receiveChannel = make(chan *CrayfishWebSocketResponseMessage, 1)
	response := <-c.receiveChannel
	log.Debugf("[textsecure-crayfish-ws] avatar recieved an response")
	rm, err := json.Marshal(response.Message)
	if err != nil {
		log.Errorln("[textsecure-crayfish-ws] failed to marshal response message", response.Message)
		return nil, err
	}
	var data CrayfishWebSocketResponse_AVATAR_MESSAGE
	err = json.Unmarshal(rm, &data)
	if err != nil {
		return nil, err
	}
	decodedAvatar, err := b64.StdEncoding.DecodeString(data.Avatar)
	if err != nil {
		return nil, err
	}
	return decodedAvatar, nil
}
