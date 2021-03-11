package groupsv2

import (
	zkgroup "github.com/nanu-c/zkgroup"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func decryptGroupJoinInfo(groupJoinInfo *signalservice.GroupJoinInfo, groupSecretParams zkgroup.GroupSecretParams) (*signalservice.DecryptedGroupJoinInfo, error) {
	decryptedGroupJoinInfo := new(signalservice.DecryptedGroupJoinInfo)
	clientZkGroupCipher := zkgroup.NewClientZkGroupCipher(groupSecretParams)
	title, err := clientZkGroupCipher.DecryptBlob(groupJoinInfo.GetTitle())
	if err != nil {
		return nil, err
	}
	decryptedGroupJoinInfo.Title = string(title)
	return decryptedGroupJoinInfo, nil
}

func getDecryptedGroupChange(change []byte, groupSecretParams zkgroup.GroupSecretParams) (*signalservice.DecryptedGroupChange, error) {
	clientZkGroupCipher := zkgroup.NewClientZkGroupCipher(groupSecretParams)

	groupChange := &signalservice.GroupChange{}
	err := proto.Unmarshal(change, groupChange)
	if err != nil {
		return nil, err
	}
	groupChangeActions := &signalservice.GroupChange_Actions{}
	err = proto.Unmarshal(groupChange.GetActions(), groupChangeActions)
	if err != nil {
		return nil, err
	}
	decryptedGroupChange := decryptGroupChangeActions(groupChangeActions, clientZkGroupCipher)

	return decryptedGroupChange, nil
}

func decryptGroupChangeActions(groupActions *signalservice.GroupChange_Actions,
	clientCipher *zkgroup.ClientZkGroupCipher) *signalservice.DecryptedGroupChange {
	decryptedGroupChange := &signalservice.DecryptedGroupChange{}
	if groupActions.SourceUuid != nil {
		uuid, err := clientCipher.DecryptUUID(groupActions.SourceUuid)
		log.Debugln("[textsecure][groupsv2] SourceUuid", idToHex(uuid), err)
	}
	log.Debugln("[textsecure][groupsv2] Revision", groupActions.Revision)
	if groupActions.AddMembers != nil {
		log.Debugln("[textsecure][groupsv2] AddMembers")
	}
	if groupActions.DeleteMembers != nil {
		log.Debugln("[textsecure][groupsv2] DeleteMembers")
		decryptDeletePendingMembers(groupActions.DeletePendingMembers, clientCipher)
	}
	if groupActions.ModifyMemberRoles != nil {
		log.Debugln("[textsecure][groupsv2] ModifyMemberRoles")
	}
	if groupActions.ModifyMemberProfileKeys != nil {
		log.Debugln("[textsecure][groupsv2] ModifyMemberProfileKeys")
	}
	if groupActions.AddPendingMembers != nil {
		log.Debugln("[textsecure][groupsv2] AddPendingMembers")
		decryptedGroupChange.NewPendingMembers = decryptPendingMembers(groupActions.AddPendingMembers, clientCipher)
	}
	if groupActions.DeletePendingMembers != nil {
		log.Debugln("[textsecure][groupsv2] DeletePendingMembers")
	}
	if groupActions.PromotePendingMembers != nil {
		log.Debugln("[textsecure][groupsv2] PromotePendingMembers")
	}
	if groupActions.ModifyTitle != nil {
		log.Debugln("[textsecure][groupsv2] ModifyTitle")
	}
	if groupActions.ModifyAvatar != nil {
		log.Debugln("[textsecure][groupsv2] ModifyAvatar")
	}
	if groupActions.ModifyDisappearingMessagesTimer != nil {
		log.Debugln("[textsecure][groupsv2] ModifyDisappearingMessagesTimer")
	}
	if groupActions.ModifyAttributesAccess != nil {
		log.Debugln("[textsecure][groupsv2] ModifyAttributesAccess")
	}
	if groupActions.ModifyMemberAccess != nil {
		log.Debugln("[textsecure][groupsv2] ModifyMemberAccess")
	}
	if groupActions.ModifyAddFromInviteLinkAccess != nil {
		log.Debugln("[textsecure][groupsv2] ModifyAddFromInviteLinkAccess")
	}
	if groupActions.AddRequestingMembers != nil {
		log.Debugln("[textsecure][groupsv2] AddRequestingMembers")
	}
	if groupActions.DeleteRequestingMembers != nil {
		log.Debugln("[textsecure][groupsv2] DeleteRequestingMembers")
	}
	if groupActions.PromoteRequestingMembers != nil {
		log.Debugln("[textsecure][groupsv2] PromoteRequestingMembers")
	}
	if groupActions.ModifyInviteLinkPassword != nil {
		log.Debugln("[textsecure][groupsv2] ModifyInviteLinkPassword")
	}
	return decryptedGroupChange
}
