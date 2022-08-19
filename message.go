package textsecure

import (
	"github.com/signal-golang/textsecure/groupsv2"
	signalservice "github.com/signal-golang/textsecure/protobuf"
)

// Message represents a message received from the peer.
// It can optionally include attachments and be sent to a group.
type Message struct {
	sourceUUID              string
	source                  string
	message                 string
	attachments             []*Attachment
	group                   *Group
	groupV2                 *groupsv2.GroupV2
	flags                   uint32
	expireTimer             uint32
	profileKey              []byte
	timestamp               uint64
	quote                   *signalservice.DataMessage_Quote
	contact                 []*signalservice.DataMessage_Contact
	sticker                 *signalservice.DataMessage_Sticker
	requiredProtocolVersion uint32
	isViewOnce              bool
	reaction                *signalservice.DataMessage_Reaction
}

// Source returns the ID of the sender of the message.
func (m *Message) Source() string {
	return m.source
}

// SourceUUID returns the UUID of the sender of the message.
func (m *Message) SourceUUID() string {
	return m.sourceUUID
}

// ChatID returns the ChatID of the sender of the message.
func (m *Message) ChatID() string {
	return m.sourceUUID
}

// Message returns the message body.
func (m *Message) Message() string {
	return m.message
}

// Attachments returns the list of attachments on the message.
func (m *Message) Attachments() []*Attachment {
	return m.attachments
}

// Group returns group information.
func (m *Message) Group() *Group {
	return m.group
}

// GroupV2 returns group information.
func (m *Message) GroupV2() *groupsv2.GroupV2 {
	return m.groupV2
}

// Timestamp returns the timestamp of the message
func (m *Message) Timestamp() uint64 {
	return m.timestamp
}

// Flags returns the flags in the message
func (m *Message) Flags() uint32 {
	return m.flags
}

// ExpireTimer returns the expire timer in the message
func (m *Message) ExpireTimer() uint32 {
	return m.expireTimer
}

// Sticker returns the sticker in the message
func (m *Message) Sticker() *signalservice.DataMessage_Sticker {
	return m.sticker
}

// Contact returns the contact in the message
func (m *Message) Contact() []*signalservice.DataMessage_Contact {
	return m.contact
}

// Quote returns the quote in the message
func (m *Message) Quote() *signalservice.DataMessage_Quote {
	return m.quote
}

// Reaction returns the reaction in the message
func (m *Message) Reaction() *signalservice.DataMessage_Reaction {
	return m.reaction
}
