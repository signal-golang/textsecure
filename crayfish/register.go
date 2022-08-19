package crayfish

import (
	"encoding/json"
	"strconv"

	uuid "github.com/satori/go.uuid"
	"github.com/signal-golang/textsecure/registration"
	log "github.com/sirupsen/logrus"
)

func (c *CrayfishInstance) CrayfishRegister(registrationInfo *registration.RegistrationInfo,
	phoneNumber string,
	captcha string) error {
	log.Debugf("[textsecure-crayfish-ws] Registering via crayfish build message")
	registerMessage := &CrayfishWebSocketRequest_REGISTER_MESSAGE{
		Number:   phoneNumber,
		Password: registrationInfo.Password,
		Captcha:  captcha,
		UseVoice: false,
	}
	messageType := CrayfishWebSocketMessage_REQUEST
	requestType := CrayfishWebSocketRequestMessageTyp_START_REGISTRATION
	request := &CrayfishWebSocketRequestMessage{
		Type:    &requestType,
		Message: registerMessage,
	}
	registerRequestMessage := &CrayfishWebSocketMessage{
		Type:    &messageType,
		Request: request,
	}
	m, err := json.Marshal(registerRequestMessage)
	if err != nil {
		return err
	}
	log.Debugf("[textsecure-crayfish-ws] Registering via crayfish send")
	c.wsconn.send <- m
	return nil
}
func (c *CrayfishInstance) CrayfishRegisterWithCode(registrationInfo *registration.RegistrationInfo,
	phoneNumber string,
	captcha string,
	code string) (*CrayfishRegistration, error) {
	codeInt, err := strconv.ParseUint(code, 10, 32)
	if err != nil {
		return nil, err
	}
	messageType := CrayfishWebSocketMessage_REQUEST
	var signalingKey [52]byte
	copy(signalingKey[:], registrationInfo.SignalingKey)
	verificationMessage := &CrayfishWebSocketRequest_VERIFY_REGISTER_MESSAGE{
		Number:       phoneNumber,
		Code:         codeInt,
		SignalingKey: signalingKey,
		Password:     registrationInfo.Password,
	}
	requestVerifyType := CrayfishWebSocketRequestMessageTyp_VERIFY_REGISTRATION
	verificationRequest := &CrayfishWebSocketRequestMessage{
		Type:    &requestVerifyType,
		Message: verificationMessage,
	}
	verificationRequestMessage := &CrayfishWebSocketMessage{
		Type:    &messageType,
		Request: verificationRequest,
	}
	mv, err := json.Marshal(verificationRequestMessage)
	if err != nil {
		return nil, err
	}
	log.Debugf("[textsecure-crayfish-ws] Registering via crayfish send verification")
	c.wsconn.send <- mv
	c.receiveChannel = make(chan *CrayfishWebSocketResponseMessage, 1)
	response := <-c.receiveChannel
	rm, err := json.Marshal(response.Message)
	if err != nil {
		return nil, err
	}
	var data CrayfishWebSocketResponse_VERIFY_REGISTER_MESSAGE
	err = json.Unmarshal(rm, &data)
	if err != nil {
		return nil, err
	}
	uuidString, err := uuid.FromBytes(data.UUID[:])
	if err != nil {
		return nil, err
	}
	log.Debugf("[textsecure-crayfish-ws] Registering via crayfish uuid %s", uuidString.String())
	return &CrayfishRegistration{
		UUID: uuidString.String(),
		Tel:  phoneNumber,
	}, nil
}
