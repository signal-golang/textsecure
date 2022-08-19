package crayfish

import (
	b64 "encoding/base64"
	"encoding/json"

	log "github.com/sirupsen/logrus"
)

func (c *CrayfishInstance) HandleEnvelope(msg []byte) (*CrayfishWebSocketResponse_HANDLE_ENVELOPE_MESSAGE, error) {
	messageType := CrayfishWebSocketMessage_REQUEST
	requestType := CrayfishWebSocketRequestMessageTyp_HANDLE_ENVELOPE
	sEnc := b64.StdEncoding.EncodeToString(msg)
	envelopeMessage := &CrayfishWebSocketRequest_HANDLE_ENVELOPE_MESSAGE{
		Message: sEnc,
	}
	log.Debugln("[textsecure-crayfish-ws] Sending envelope")

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
	log.Debugf("[textsecure-crayfish-ws] HandleEnvelope send")
	c.wsconn.send <- m
	c.receiveChannel = make(chan *CrayfishWebSocketResponseMessage, 1)
	response := <-c.receiveChannel
	log.Debugf("[textsecure-crayfish-ws] HandleEnvelope recieved an response")
	rm, err := json.Marshal(response.Message)
	if err != nil {
		log.Errorln("[textsecure-crayfish-ws] failed to marshal response message", response.Message)
		return nil, err
	}
	var data CrayfishWebSocketResponse_HANDLE_ENVELOPE_MESSAGE
	err = json.Unmarshal(rm, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}
