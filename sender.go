package textsecure

import (
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/signal-golang/textsecure/config"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	"github.com/signal-golang/textsecure/unidentifiedAccess"
	log "github.com/sirupsen/logrus"
)

func sendMessage(msg *outgoingMessage) (uint64, error) {
	// todo use UnidentifiedSenderMessage

	if _, ok := deviceLists[msg.destination]; !ok {
		deviceLists[msg.destination] = []uint32{1}
	}

	dm := createMessage(msg)

	content := &signalservice.Content{
		DataMessage: dm,
	}
	b, err := proto.Marshal(content)
	if err != nil {
		return 0, err
	}

	resp, err := buildAndSendMessage(msg.destination, padMessage(b), false, dm.Timestamp)
	if err != nil {
		return 0, err
	}
	var e164 *string
	var uuid *string

	if msg.destination[0] == '+' {
		e164 = &msg.destination
	} else {
		uuid = &msg.destination
	}

	if resp.NeedsSync {
		log.Debugf("[textsecure] Needs sync. destination: %s", msg.destination)
		sm := &signalservice.SyncMessage{
			Sent: &signalservice.SyncMessage_Sent{
				DestinationE164: e164,
				DestinationUuid: uuid,
				Timestamp:       dm.Timestamp,
				Message:         dm,
			},
		}

		_, serr := sendSyncMessage(sm, dm.Timestamp)
		if serr != nil {
			log.WithFields(log.Fields{
				"error":       serr,
				"destination": msg.destination,
				"timestamp":   resp.Timestamp,
			}).Error("Failed to send sync message")
		}
	}
	return resp.Timestamp, err
}

// TODO switch to uuids
func sendSyncMessage(sm *signalservice.SyncMessage, timestamp *uint64) (uint64, error) {
	log.Debugln("[textsecure] sendSyncMessage", timestamp)
	user := config.ConfigFile.Tel //TODO: switch tu uuid
	if config.ConfigFile.UUID != "" {
		user = config.ConfigFile.UUID
	}
	if _, ok := deviceLists[user]; !ok {
		deviceLists[user] = []uint32{1}
	}

	content := &signalservice.Content{
		SyncMessage: sm,
	}

	b, err := proto.Marshal(content)
	if err != nil {
		return 0, err
	}

	resp, err := buildAndSendMessage(user, padMessage(b), true, timestamp)
	return resp.Timestamp, err
}

func sendVerifiedMessage(verified *signalservice.Verified, unidentifiedAccess *unidentifiedAccess.UnidentifiedAccess) error {
	omsg := &outgoingNullMessage{
		destination: verified.GetDestinationUuid(),
		msg: &signalservice.NullMessage{
			Padding: []byte{},
		},
	}
	_, err := sendNullMessage(omsg)
	return err
}

type outgoingNullMessage struct {
	destination string
	msg         *signalservice.NullMessage
}

func sendNullMessage(msg *outgoingNullMessage) (uint64, error) {
	if _, ok := deviceLists[msg.destination]; !ok {
		deviceLists[msg.destination] = []uint32{1}
	}

	content := &signalservice.Content{
		NullMessage: msg.msg,
	}
	b, err := proto.Marshal(content)
	if err != nil {
		return 0, err
	}

	now := uint64(time.Now().UnixNano() / 1000000)

	resp, err := buildAndSendMessage(msg.destination, padMessage(b), false, &now)
	if err != nil {
		return 0, err
	}

	if resp.NeedsSync {
		log.Debugf("[textsecure] Nullmessage needs sync. destination: %s", msg.destination)
	}
	return resp.Timestamp, err
}
