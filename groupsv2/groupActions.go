package groupsv2

import (
	zkgroup "github.com/nanu-c/zkgroup"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func (g *GroupV2) decryptGroupJoinInfo(groupJoinInfo *signalservice.GroupJoinInfo, groupSecretParams zkgroup.GroupSecretParams) (*signalservice.DecryptedGroupJoinInfo, error) {
	decryptedGroupJoinInfo := new(signalservice.DecryptedGroupJoinInfo)
	clientZkGroupCipher := zkgroup.NewClientZkGroupCipher(groupSecretParams)
	title, err := clientZkGroupCipher.DecryptBlob(groupJoinInfo.GetTitle())
	if err != nil {
		return nil, err
	}
	decryptedGroupJoinInfo.Title = string(title)
	return decryptedGroupJoinInfo, nil
}

func (g *GroupV2) getDecryptedGroupChange(change []byte, groupSecretParams zkgroup.GroupSecretParams) (*signalservice.DecryptedGroupChange, error) {

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
	decryptedGroupChange := g.decryptGroupChangeActions(groupChangeActions)

	return decryptedGroupChange, nil
}

// todo error handling
// todo decryption of everything
func (g *GroupV2) decryptGroupChangeActions(groupActions *signalservice.GroupChange_Actions) *signalservice.DecryptedGroupChange {
	err := g.checkCipher()
	if err != nil {
		return nil
	}
	decryptedGroupChange := &signalservice.DecryptedGroupChange{
		Revision: groupActions.GetRevision(),
	}
	if groupActions.SourceUuid != nil {
		uuid, err := g.cipher.DecryptUUID(groupActions.SourceUuid)
		log.Debugln("[textsecure][groupsv2] SourceUuid", idToHex(uuid), err)
	}
	log.Debugln("[textsecure][groupsv2] Revision", groupActions.Revision)
	if groupActions.AddMembers != nil {
		log.Debugln("[textsecure][groupsv2] AddMembers")
		decryptedAddMembers := []*signalservice.DecryptedMember{}
		for _, member := range groupActions.AddMembers {
			decryptedMember, err := g.decryptMember(member.Added)
			if err == nil {
				decryptedAddMembers = append(decryptedAddMembers, decryptedMember)
			}
		}
		decryptedGroupChange.NewMembers = decryptedAddMembers
	}
	if groupActions.DeleteMembers != nil {
		log.Debugln("[textsecure][groupsv2] DeleteMembers")
		decryptedDeleteMembers := [][]byte{}
		for _, member := range groupActions.DeleteMembers {
			decryptedMember, err := g.decryptUUID(member.DeletedUserId)
			if err == nil {
				decryptedDeleteMembers = append(decryptedDeleteMembers, decryptedMember)
			}
		}
		decryptedGroupChange.DeleteMembers = decryptedDeleteMembers
	}
	if groupActions.ModifyMemberRoles != nil {
		log.Debugln("[textsecure][groupsv2] ModifyMemberRoles")
		decryptedModifyMemberRoles := []*signalservice.DecryptedModifyMemberRole{}
		for _, member := range groupActions.ModifyMemberRoles {
			decryptedMember, err := g.decryptUUID(member.UserId)

			if err == nil {
				decryptedModifyMemberRole := signalservice.DecryptedModifyMemberRole{
					Uuid: decryptedMember,
					Role: member.Role,
				}
				decryptedModifyMemberRoles = append(decryptedModifyMemberRoles, &decryptedModifyMemberRole)
			}
		}
		decryptedGroupChange.ModifyMemberRoles = decryptedModifyMemberRoles
	}
	if groupActions.ModifyMemberProfileKeys != nil {
		log.Debugln("[textsecure][groupsv2] ModifyMemberProfileKeys")
	}
	if groupActions.AddPendingMembers != nil {
		log.Debugln("[textsecure][groupsv2] AddPendingMembers")
		decryptedGroupChange.NewPendingMembers = g.decryptPendingMembers(groupActions.AddPendingMembers)
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
