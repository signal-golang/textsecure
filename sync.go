package textsecure

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"

	"github.com/golang/protobuf/proto"
	"github.com/signal-golang/textsecure/config"
	"github.com/signal-golang/textsecure/contacts"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	"github.com/signal-golang/textsecure/unidentifiedAccess"
	log "github.com/sirupsen/logrus"
)

// handleSyncMessage handles an incoming SyncMessage.
func handleSyncMessage(src string, srcUUID string, timestamp uint64, sm *signalservice.SyncMessage) error {
	log.Debugf("[textsecure] SyncMessage recieved at %d", timestamp)
	if sm.GetSent() != nil {
		log.Debugln("[textsecure] SyncMessage getSent")
		return handleSyncSent(sm.GetSent(), timestamp)
	} else if sm.GetContacts() != nil {
		log.Debugln("[textsecure] SyncMessage unhandled contacts")
		return nil
	} else if sm.GetGroups() != nil {
		log.Debugln("[textsecure] SyncMessage groups")
		return nil
	} else if sm.GetRequest() != nil {
		log.Debugln("[textsecure] SyncMessage getRequest")
		return handleSyncRequest(sm.GetRequest())
	} else if sm.GetRead() != nil {
		log.Debugln("[textsecure] SyncMessage getRead")
		return handleSyncRead(sm.GetRead())
	} else if sm.GetBlocked() != nil {
		log.Debugln("[textsecure] SyncMessage unhandled getBlocked")
		return nil
	} else if sm.GetVerified() != nil {
		log.Debugln("[textsecure] SyncMessage verified")
		unidentifiedAccess, err := unidentifiedAccess.GetAccessForSync(config.ConfigFile.ProfileKey, config.ConfigFile.Certificate)
		if err != nil {
			return err
		}
		return sendVerifiedMessage(sm.GetVerified(), unidentifiedAccess)
	} else if sm.GetConfiguration() != nil {
		log.Debugln("[textsecure] SyncMessage unahndled configuration")
		return nil
	} else if sm.GetPadding() != nil {
		log.Debugln("[textsecure] SyncMessage unhandled padding")
		return nil
	} else if sm.GetStickerPackOperation() != nil {
		log.Debugln("[textsecure] SyncMessage unhandled GetStickerPackOperation")
		return nil
	} else if sm.GetViewOnceOpen() != nil {
		log.Debugln("[textsecure] SyncMessage unhandled GetViewOnceOpen")
		return nil
	} else if sm.GetFetchLatest() != nil {
		log.Debugln("[textsecure] SyncMessage unhandled GetFetchLatest")
		return nil
	} else if sm.GetKeys() != nil {
		log.Debugln("[textsecure] SyncMessage unhandled GetKeys")
		return nil
	} else if sm.GetMessageRequestResponse() != nil {
		log.Debugln("[textsecure] SyncMessage unhandled GetMessageRequestResponse")
		return nil
	} else if sm.GetOutgoingPayment() != nil {
		log.Debugln("[textsecure] SyncMessage unhandled GetOutgoing payment")
		return nil
	} else if sm.GetViewed() != nil {
		log.Debugln("[textsecure] SyncMessage unhandled getViewed")
		return nil
	} else if sm.GetPniIdentity() != nil {
		log.Debug("[textsecure] SyncMessage unhandled getPniIdentity")
		return nil
	} else if sm.GetPniChangeNumber() != nil {
		log.Debugln("[textsecure] SyncMessage unhandled getPniChangeNumber")
		return nil
	} else {
		log.Errorf("[textsecure] SyncMessage contains no known sync types")
	}

	return nil
}

// handleSyncSent handles sync sent messages
func handleSyncSent(s *signalservice.SyncMessage_Sent, ts uint64) error {
	dm := s.GetMessage()
	dest := s.GetDestinationE164()

	if dm == nil {
		return fmt.Errorf("DataMessage was nil for SyncMessage_Sent")
	}

	flags, err := handleFlags(dest, dm)
	if err != nil {
		return err
	}

	atts, err := handleAttachments(dm)
	if err != nil {
		return err
	}
	grV2, err := handleGroupsV2(dest, dm)
	if err != nil {
		return err
	}
	cs, err := contacts.HandleContacts(dest, dm)
	if err != nil {
		return err
	}

	msg := &Message{
		source:      dest,
		message:     dm.GetBody(),
		attachments: atts,
		groupV2:     grV2,
		contact:     cs,
		flags:       flags,
		expireTimer: dm.GetExpireTimer(),
		profileKey:  dm.GetProfileKey(),
		timestamp:   *dm.Timestamp,
		quote:       dm.GetQuote(),
		sticker:     dm.GetSticker(),
		reaction:    dm.GetReaction(),
	}

	if client.SyncSentHandler != nil {
		client.SyncSentHandler(msg, ts)
	}

	return nil
}

// handleSyncRequestMessage
func handleSyncRequest(request *signalservice.SyncMessage_Request) error {
	if request.GetType() == signalservice.SyncMessage_Request_CONTACTS {
		return sendContactUpdate()
	} else if request.GetType() == signalservice.SyncMessage_Request_GROUPS {
		return sendGroupUpdate()
	} else {
		log.Debugln("[textsecure] handle sync request unhandled type", request.GetType())
	}

	return nil
}

func isValidUUID(uuid string) bool {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	return r.MatchString(uuid)
}

// sendContactUpdate
func sendContactUpdate() error {
	log.Debugf("[textsecure] Sending contact SyncMessage")

	lc, err := GetRegisteredContacts()
	if err != nil {
		return fmt.Errorf("could not get local contacts: %s", err)
	}

	var buf bytes.Buffer

	for _, contact := range lc {
		if isValidUUID(contact.UUID) {
			cd := &signalservice.ContactDetails{
				Number:      &contact.Tel,
				Uuid:        &contact.UUID,
				Name:        &contact.Name,
				Color:       &contact.Color,
				Verified:    contact.Verified,
				Blocked:     &contact.Blocked,
				ExpireTimer: &contact.ExpireTimer,

				// TODO: handle avatars
			}

			b, err := proto.Marshal(cd)
			if err != nil {
				log.Errorf("[textsecure] Failed to marshal contact details")
				continue
			}

			buf.Write(varint32(len(b)))
			buf.Write(b)
		}

	}

	attachmentPointer, err := uploadAttachment(&buf, "application/octet-stream")
	if err != nil {
		return err
	}

	sm := &signalservice.SyncMessage{
		Contacts: &signalservice.SyncMessage_Contacts{
			Blob: &signalservice.AttachmentPointer{
				AttachmentIdentifier: &signalservice.AttachmentPointer_CdnKey{
					CdnKey: attachmentPointer.cdnKey,
				},
				CdnNumber:   &attachmentPointer.cdnNr,
				ContentType: &attachmentPointer.ct,
				Key:         attachmentPointer.keys[:],
				Digest:      attachmentPointer.digest[:],
				Size:        &attachmentPointer.size,
			},
		},
	}
	_, err = sendSyncMessage(sm, nil)
	return err
}

// sendGroupUpdate
func sendGroupUpdate() error {
	log.Debugf("Sending group SyncMessage")

	var buf bytes.Buffer

	for _, g := range groups {
		gd := &signalservice.GroupDetails{
			Id:          g.ID,
			Name:        &g.Name,
			MembersE164: g.Members,
			// XXX add support for avatar
			// XXX add support for active?
		}

		b, err := proto.Marshal(gd)
		if err != nil {
			log.Errorf("Failed to marshal group details")
			continue
		}

		buf.Write(varint32(len(b)))
		buf.Write(b)
	}

	attachmentPointer, err := uploadAttachment(&buf, "application/octet-stream")
	if err != nil {
		return err
	}

	sm := &signalservice.SyncMessage{
		Groups: &signalservice.SyncMessage_Groups{
			Blob: &signalservice.AttachmentPointer{
				AttachmentIdentifier: &signalservice.AttachmentPointer_CdnKey{
					CdnKey: attachmentPointer.cdnKey,
				},
				CdnNumber:   &attachmentPointer.cdnNr,
				ContentType: &attachmentPointer.ct,
				Key:         attachmentPointer.keys[:],
				Digest:      attachmentPointer.digest[:],
				Size:        &attachmentPointer.size,
			},
		},
	}
	_, err = sendSyncMessage(sm, nil)
	return err
}

func handleSyncRead(readMessages []*signalservice.SyncMessage_Read) error {
	if client.SyncReadHandler != nil {
		for _, s := range readMessages {
			client.SyncReadHandler(s.GetSenderUuid(), s.GetTimestamp())
		}
	}

	return nil
}

// Encodes a 32bit base 128 variable-length integer and returns the bytes
func varint32(value int) []byte {
	buf := make([]byte, binary.MaxVarintLen32)
	n := binary.PutUvarint(buf, uint64(value))
	return buf[:n]
}
