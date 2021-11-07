package textsecure

import (
	"github.com/golang/protobuf/proto"
	"github.com/signal-golang/textsecure/config"
	"github.com/signal-golang/textsecure/groupsv2"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	log "github.com/sirupsen/logrus"
)

func handleMessage(srcE164 string, srcUUID string, timestamp uint64, b []byte) error {
	b = stripPadding(b)

	content := &signalservice.Content{}
	err := proto.Unmarshal(b, content)
	if err != nil {
		return err
	}

	if dm := content.GetDataMessage(); dm != nil {
		return handleDataMessage(srcE164, srcUUID, timestamp, dm)
	} else if sm := content.GetSyncMessage(); sm != nil && config.ConfigFile.Tel == srcE164 {
		return handleSyncMessage(srcE164, srcUUID, timestamp, sm)
	} else if cm := content.GetCallMessage(); cm != nil {
		return handleCallMessage(srcE164, srcUUID, timestamp, cm)
	} else if rm := content.GetReceiptMessage(); rm != nil {
		return handleReceiptMessage(srcE164, srcUUID, timestamp, rm)
	} else if tm := content.GetTypingMessage(); tm != nil {
		return handleTypingMessage(srcE164, srcUUID, timestamp, tm)
	} else if nm := content.GetNullMessage(); nm != nil {
		log.Errorln("[textsecure] Nullmessage content received", content)
		return nil
	}
	//FIXME get the right content
	// log.Errorf(content)
	log.Errorln("[textsecure] Unknown message content received", content)
	return nil
}

func handleTypingMessage(src string, srcUUID string, timestamp uint64, cm *signalservice.TypingMessage) error {

	msg := &Message{
		source:     src,
		sourceUUID: srcUUID,
		message:    "typingMessage",
		timestamp:  timestamp,
	}

	if client.TypingMessageHandler != nil {
		client.TypingMessageHandler(msg)
	}
	return nil
}
func handleReceiptMessage(src string, srcUUID string, timestamp uint64, cm *signalservice.ReceiptMessage) error {
	msg := &Message{
		source:     src,
		sourceUUID: srcUUID,
		message:    "sentReceiptMessage",
		timestamp:  cm.GetTimestamp()[0],
	}
	if *cm.Type == signalservice.ReceiptMessage_READ {
		msg.message = "readReceiptMessage"
	}
	if *cm.Type == signalservice.ReceiptMessage_DELIVERY {
		msg.message = "deliveryReceiptMessage"
	}
	if client.ReceiptMessageHandler != nil {
		client.ReceiptMessageHandler(msg)
	}

	return nil
}

// handleDataMessage handles an incoming DataMessage and calls client callbacks
func handleDataMessage(src string, srcUUID string, timestamp uint64, dm *signalservice.DataMessage) error {
	flags, err := handleFlags(srcUUID, dm)
	if err != nil {
		return err
	}

	atts, err := handleAttachments(dm)
	if err != nil {
		return err
	}
	log.Debugln("[textsecure] handleDataMessage", timestamp, *dm.Timestamp, dm.GetExpireTimer())
	gr, err := handleGroups(src, dm)
	if err != nil {
		return err
	}
	gr2, err := groupsv2.HandleGroupsV2(src, dm)
	if err != nil {
		return err
	}
	msg := &Message{
		source:      src,
		sourceUUID:  srcUUID,
		message:     dm.GetBody(),
		attachments: atts,
		group:       gr,
		groupV2:     gr2,
		flags:       flags,
		expireTimer: dm.GetExpireTimer(),
		profileKey:  dm.GetProfileKey(),
		timestamp:   *dm.Timestamp,
		quote:       dm.GetQuote(),
		contact:     dm.GetContact(),
		preview:     dm.GetPreview(),
		sticker:     dm.GetSticker(),
		reaction:    dm.GetReaction(),
		// requiredProtocolVersion: dm.GetRequiredProtocolVersion(),
		// isViewOnce: *dm.IsViewOnce,
	}

	if client.MessageHandler != nil {
		client.MessageHandler(msg)
	}
	return nil
}
func handleCallMessage(src string, srcUUID string, timestamp uint64, cm *signalservice.CallMessage) error {
	message := "Call "
	if m := cm.GetAnswer(); m != nil {
		message += "answer"
	}
	if m := cm.GetOffer(); m != nil {
		message += "offer"
	}
	if m := cm.GetHangup(); m != nil {
		message += "hangup"
	}
	if m := cm.GetBusy(); m != nil {
		message += "busy"
	}
	if m := cm.GetLegacyHangup(); m != nil {
		message += "hangup"
	}
	// if m := cm.GetMultiRing(); m == true {
	// 	message += "ring "
	// }
	if m := cm.GetIceUpdate(); m != nil {
		message += "ring"
	}
	// if m := cm.GetOpaque(); m != nil {
	// 	message += "opaque"
	// }

	msg := &Message{
		source:     src,
		sourceUUID: srcUUID,
		message:    message,
		timestamp:  timestamp,
	}

	if client.MessageHandler != nil {
		client.MessageHandler(msg)
	}
	return nil
}

func handleUnidentifiedSenderMessage(srcUUID string, timestamp uint64, sm *signalservice.SyncMessage) error {
	return nil
}
