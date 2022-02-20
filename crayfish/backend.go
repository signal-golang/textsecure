package crayfish

import (
	"crypto/tls"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	// "github.com/nanu-c/textsecure/app/ui"
	uuid "github.com/satori/go.uuid"
	"github.com/signal-golang/textsecure/registration"
	"github.com/signal-golang/textsecure/rootCa"
	log "github.com/sirupsen/logrus"
)

var (
	Instance *CrayfishInstance
	// ErrNotListening is returned when trying to stop listening when there's no
	// valid listening connection set up
	ErrNotListening = errors.New("[textsecure-crayfish-ws] there is no listening connection to stop")
)

type CrayfishInstance struct {
	wsconn         *Conn
	cmd            *exec.Cmd
	stopping       bool
	receiveChannel chan *CrayfishWebSocketResponseMessage
}

type CrayfishRegistration struct {
	UUID string `json:"uuid"`
	Tel  string `json:"tel"`
}

const (
	// Time allowed to write a message to the peer.
	writeWait = 25 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Signal websocket endpoint
	websocketPath = "/libsignal"
	serverAdress  = "ws://localhost:9081"
)

type CrayfishWebSocketMessageType int32

const (
	CrayfishWebSocketMessage_UNKNOWN  CrayfishWebSocketMessageType = 0
	CrayfishWebSocketMessage_REQUEST  CrayfishWebSocketMessageType = 1
	CrayfishWebSocketMessage_RESPONSE CrayfishWebSocketMessageType = 2
)

type CrayfishWebSocketMessage struct {
	Type     *CrayfishWebSocketMessageType     `json:"type,omitempty"`
	Request  *CrayfishWebSocketRequestMessage  `json:"request,omitempty"`
	Response *CrayfishWebSocketResponseMessage `json:"response,omitempty"`
}
type CrayfishWebSocketRequestMessageType int32

const (
	CrayfishWebSocketRequestMessageTyp_UNKNOWN             CrayfishWebSocketRequestMessageType = 0
	CrayfishWebSocketRequestMessageTyp_START_REGISTRATION  CrayfishWebSocketRequestMessageType = 1
	CrayfishWebSocketRequestMessageTyp_VERIFY_REGISTRATION CrayfishWebSocketRequestMessageType = 2
	CrayfishWebSocketRequestMessageTyp_HANDLE_ENVELOPE     CrayfishWebSocketRequestMessageType = 3
)

type CrayfishWebSocketRequestMessage struct {
	Type    *CrayfishWebSocketRequestMessageType `json:"type,omitempty"`
	Message interface{}                          `json:"message,omitempty"`
}

type CrayfishWebSocketResponseMessageType int32

const (
	CrayfishWebSocketResponseMessageTyp_UNKNOWN             CrayfishWebSocketResponseMessageType = 0
	CrayfishWebSocketResponseMessageTyp_ACK                 CrayfishWebSocketResponseMessageType = 1
	CrayfishWebSocketResponseMessageTyp_VERIFY_REGISTRATION CrayfishWebSocketResponseMessageType = 2
	CrayfishWebSocketResponseMessageTyp_HANDLE_ENVELOPE     CrayfishWebSocketResponseMessageType = 3
)

type CrayfishWebSocketResponseMessage struct {
	Type    *CrayfishWebSocketResponseMessageType `json:"type,omitempty"`
	Message interface{}                           `json:"message,omitempty"`
}

type ACKMessage struct {
	Status string `json:"status"`
}

// Conn is a wrapper for the websocket connection
type Conn struct {
	// The websocket connection
	ws *websocket.Conn

	// Buffered channel of outbound messages
	send chan []byte
}

type CrayfishWebSocketRequest_REGISTER_MESSAGE struct {
	Number   string `json:"number"`
	Password string `json:"password"`
	Captcha  string `json:"captcha"`
	UseVoice bool   `json:"use_voice"`
}

type CrayfishWebSocketRequest_VERIFY_REGISTER_MESSAGE struct {
	Code         uint64   `json:"confirm_code"`
	Number       string   `json:"number"`
	Password     string   `json:"password"`
	SignalingKey [52]byte `json:"signaling_key"`
}

type CrayfishWebSocketRequestMessageTyp_SEALED_SESSION_DECRYPT_Message struct {
}
type CrayfishWebSocketResponse_VERIFY_REGISTER_MESSAGE struct {
	UUID           [16]byte `json:"uuid"`
	StorageCapable bool     `json:"storage_capable"`
}
type CrayfishWebSocketRequest_HANDLE_ENVELOPE_MESSAGE struct {
	Message string `json:"message"`
}
type CrayfishWebSocketResponse_HANDLE_ENVELOPE_MESSAGE struct {
	Message      string `json:"message"`
	Timestamp    int64  `json:"timestamp"`
	SenderDevice int32  `json:"sender_device"`
	Sender       Sender `json:"sender"`
}
type Sender struct {
	UUID        string      `json:"uuid"`
	PhoneNumber PhoneNumber `json:"phonenumber"`
}
type PhoneNumber struct {
	Code     PhoneNumberCode     `json:"code"`
	National PhoneNumberNational `json:"national,string,omitempty"`
}
type PhoneNumberCode struct {
	Value  uint64 `json:"value"`
	Source string `json:"source"`
}
type PhoneNumberNational struct {
	Value uint64 `json:"value"`
	Zeros int    `json:"zeros"`
}

func Run() {
	Instance = &CrayfishInstance{}
	log.Infoln("[textsecure-crayfish] Starting crayfish-backend")
	path, err := exec.LookPath("crayfish")
	if err != nil {
		if _, err := os.OpenFile("./crayfish", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600); err == nil {
			Instance.cmd = exec.Command("./crayfish")
		} else if _, err := os.Stat("./crayfish/target/debug/crayfish"); err == nil {
			Instance.cmd = exec.Command("./crayfish/target/debug/crayfish")
		} else {
			log.Errorln("[textsecure-crayfish] crayfish not found textsecure doesn't work without crayfish")
			log.Errorln("[textsecure-crayfish] Please install crayfish, hints are in the README at https://github.com/signal-golang/textsecure")
			Instance.cmd = exec.Command("pwd")
			os.Exit(1)
		}
	} else {
		Instance.cmd = exec.Command(path)
	}
	var stdout, stderr []byte
	var errStdout, errStderr error
	stdoutIn, _ := Instance.cmd.StdoutPipe()
	stderrIn, _ := Instance.cmd.StderrPipe()
	Instance.cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}
	err = Instance.cmd.Start()
	if err != nil {
		log.Fatalf("[textsecure-crayfish] Starting crayfish-backend Instance.cmd.Start() failed with '%s'\n", err)
	}

	go Instance.StartListening()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		stdout, errStdout = copyAndCapture(os.Stdout, stdoutIn)
		wg.Done()
	}()
	stderr, errStderr = copyAndCapture(os.Stderr, stderrIn)
	wg.Wait()

	err = Instance.cmd.Wait()
	if err != nil {
		log.Errorf("[textsecure-crayfish] Starting crayfish-backend c.cmd.Wait() failed with '%s'\n", err)
		return
	}
	if errStdout != nil || errStderr != nil {
		log.Fatal("[textsecure-crayfish] failed to capture stdout or stderr\n")
	}
	outStr, errStr := string(stdout), string(stderr)
	log.Infof("[textsecure-crayfish-ws] out: %s\n", outStr)
	log.Infof("[textsecure-crayfish-ws] err: %s\n", errStr)
	log.Infof("[textsecure-crayfish] Crayfish-backend finished with error: %v", err)
	Instance.cmd.Process.Kill()

}
func copyAndCapture(w io.Writer, r io.Reader) ([]byte, error) {
	var out []byte
	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			d := buf[:n]
			out = append(out, d...)
			log.Println("[crayfish]", string(d))
			// _, err := w.Write(d)
			if err != nil {
				return out, err
			}
		}
		if err != nil {
			// Read returns io.EOF at the end of file, which is not an error for us
			if err == io.EOF {
				err = nil
			}
			return out, err
		}
	}
}

// Connect to Signal websocket API at originURL with user and pass credentials
func (c *Conn) connect(originURL string) error {
	u, _ := url.Parse(originURL)

	log.Debugf("[textsecure-crayfish-ws] websocket connecting to crayfish-server")

	var err error
	d := &websocket.Dialer{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	d.NetDial = func(network, addr string) (net.Conn, error) { return net.Dial(network, u.Host) }
	d.TLSClientConfig = &tls.Config{
		RootCAs: rootCa.RootCA,
	}

	c.ws, _, err = d.Dial(u.String(), nil)
	if err != nil {
		return err
	}

	log.Debugf("[textsecure-crayfish-ws] websocket Connected successfully")

	return nil
}

// Send ack response message
func (c *Conn) sendAck() error {
	typ := CrayfishWebSocketMessage_RESPONSE
	message := ACKMessage{
		Status: "ok",
	}
	responseType := CrayfishWebSocketResponseMessageTyp_ACK
	csm := &CrayfishWebSocketMessage{
		Type: &typ,
		Response: &CrayfishWebSocketResponseMessage{
			Type:    &responseType,
			Message: &message,
		},
	}

	b, err := json.Marshal(csm)
	if err != nil {
		return err
	}
	log.Debugln("[textsecure-crayfish-ws] websocket sending ack response ")

	c.send <- b
	return nil
}

// write writes a message with the given message type and payload.
func (c *Conn) write(mt int, payload []byte) error {
	Instance.cmd.Process.Signal(syscall.SIGCONT)
	c.ws.SetWriteDeadline(time.Now().Add(writeWait))
	return c.ws.WriteMessage(mt, payload)
}

// writeWorker writes messages to websocket connection
func (c *Conn) writeWorker() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		log.Debugf("[textsecure-crayfish-ws] closing writeWorker")
		ticker.Stop()
		c.ws.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			log.Debugln("[textsecure-crayfish-ws] incoming ws send message")
			if !ok {
				log.Errorf("[textsecure-crayfish-ws] failed to read message from channel")
				c.write(websocket.CloseMessage, []byte{})
				return
			}

			log.Debugf("[textsecure-crayfish-ws] websocket sending message")
			if err := c.write(websocket.TextMessage, message); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("[textsecure-crayfish-ws] Failed to send websocket message")
				return
			}
		case <-ticker.C:
			log.Debugf("[textsecure-crayfish-ws] Sending websocket ping message")
			if err := c.write(websocket.PingMessage, nil); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("[textsecure-crayfish-ws] Failed to send websocket ping message")
				return
			}
		}
	}
}
func (c *CrayfishInstance) StartListening() error {
	// ensure crayfish started, so we delay the start of the listener for a bit
	time.Sleep(1 * time.Second)
	defer func() {
		log.Debugf("[textsecure-crayfish-ws] BackendStartListening")
		for {
			if !c.stopping {
				err := c.StartWebsocket()
				if err != nil && !c.stopping {
					log.WithFields(log.Fields{
						"error": err,
					}).Error("[textsecure-crayfish-ws] Failed to start listening")
					time.Sleep(time.Second * 2)
				}
			} else {
				break
			}
		}
	}()
	return nil

}

// BackendStartWebsocket connects to the server and handles incoming websocket messages.
func (c *CrayfishInstance) StartWebsocket() error {
	var err error

	c.wsconn = &Conn{send: make(chan []byte, 256)}
	err = c.wsconn.connect(serverAdress + websocketPath)
	if err != nil {
		log.Errorf(err.Error())
		return err
	}

	defer c.wsconn.ws.Close()

	// Can only have a single goroutine call write methods
	go c.wsconn.writeWorker()

	c.wsconn.ws.SetReadDeadline(time.Now().Add(pongWait))
	c.wsconn.ws.SetPongHandler(func(string) error {
		log.Debugf("[textsecure-crayfish-ws] Received websocket pong message")
		c.wsconn.ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, bmsg, err := c.wsconn.ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Debugf("[textsecure-crayfish-ws] Websocket UnexpectedCloseError: %s", err)
			}
			return err
		}
		log.Debugln("[textsecure-crayfish-ws] incoming msg")
		csm := &CrayfishWebSocketMessage{}
		err = json.Unmarshal(bmsg, csm)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("[textsecure-crayfish-ws] Failed to unmarshal websocket message")
			return err
		}
		if csm.Type == nil {
			log.Errorln("[textsecure-crayfish-ws] Websocket message type is nil", string(bmsg))
		} else if *csm.Type == CrayfishWebSocketMessage_REQUEST {
			err = handleCrayfishRequestMessage(csm.Request)
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("[textsecure-crayfish-ws] Failed to handle received request message")
			}
		} else if *csm.Type == CrayfishWebSocketMessage_RESPONSE {
			err = c.handleCrayfishResponseMessage(csm.Response)
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("[textsecure-crayfish-ws] Failed to handle received request message")
			}

		} else {
			log.Errorln("[textsecure-crayfish-ws] failed to handle incoming websocket message")
		}
		if csm.Type != nil {
			err = c.wsconn.sendAck()
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("[textsecure-crayfish-ws] Failed to send ack")
				return err
			}
		}
	}
}

// StopListening disables the receiving of messages.
func (c *CrayfishInstance) StopListening() error {
	if c.wsconn == nil {
		return ErrNotListening
	}
	if c.wsconn.ws != nil {
		c.wsconn.ws.Close()
	}
	return nil
}

func handleCrayfishRequestMessage(request *CrayfishWebSocketRequestMessage) error {
	log.Debugln("[textsecure-crayfish-ws] Received websocket request message", *request.Type)
	return nil
}

func (c *CrayfishInstance) handleCrayfishResponseMessage(response *CrayfishWebSocketResponseMessage) error {
	log.Debugln("[textsecure-crayfish-ws] Received websocket response message", *response.Type)
	if c.receiveChannel != nil && *response.Type > 1 {
		c.receiveChannel <- response
	}
	return nil
}

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

func (c *CrayfishInstance) Stop() error {
	c.stopping = true
	err := c.StopListening()
	if err != nil {
		return err
	}
	if c.cmd != nil {
		err = c.cmd.Process.Signal(os.Interrupt)
		if err != nil {
			return err
		}
	}
	return nil
}

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
