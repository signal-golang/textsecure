package crayfish

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
type CrayfishRegistration struct {
	UUID string `json:"uuid"`
	Tel  string `json:"tel"`
}

type CrayfishWebSocketRequest_AVATAR_MESSAGE struct {
	Avatar string   `json:"avatar"`
	Key    [32]byte `json:"key"`
}

type CrayfishWebSocketResponse_AVATAR_MESSAGE struct {
	Avatar string `json:"avatar"`
}
