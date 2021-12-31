package groupsv2

import (
	"encoding/base64"
	"net/http"

	zkgroup "github.com/nanu-c/zkgroup"
	"github.com/signal-golang/textsecure/entities"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	"github.com/signal-golang/textsecure/utils"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	iNVITE_LINKS_CHANGE_EPOCH       uint32 = 1
	dESCRIPTION_CHANGE_EPOCH        uint32 = 2
	aNNOUNCEMENTS_ONLY_CHANGE_EPOCH uint32 = 3
)

func (g *GroupV2) ModifyGroup(user *entities.GroupUser, inviteLinkPasswordString string, submittedActions signalservice.GroupChange_Actions) (*entities.Resp, error) {
	groupChangeApplicator := GroupChangeApplicator{}
	groupValidator := GroupValidator{}
	// check path param
	var inviteLinkPassword []byte
	if len(inviteLinkPasswordString) != 0 {
		if passwd, err := base64.StdEncoding.DecodeString(inviteLinkPasswordString); err != nil {
			return nil, entities.Status(http.StatusInternalServerError, err.Error())
		} else {
			inviteLinkPassword = passwd
		}
	}

	log.Infoln("[textsecure]=====================submittedActions=============")
	log.Infoln("[textsecure]", submittedActions.String())
	log.Infoln("[textsecure] =====================submittedActions=============")

	//submittedActions.AddMembers
	err := groupValidator.ValidateAddMember(user, inviteLinkPassword, g, submittedActions.AddMembers, g.MasterKey) //?
	if err != nil {
		return nil, entities.Status(http.StatusBadRequest, err.Error())
	}
	// submittedActions.AddMembersPendingProfileKey
	err = groupValidator.ValidateAddMembersPendingProfileKey(user, g, submittedActions.AddPendingMembers)
	if err != nil {
		return nil, entities.Status(http.StatusBadRequest, err.Error())
	}
	// AddMembersPendingAdminApproval

	err = groupValidator.ValidateAddMembersPendingAdminApproval(user, inviteLinkPassword, g, submittedActions.AddRequestingMembers)
	if err != nil {
		return nil, entities.Status(http.StatusBadRequest, err.Error())
	}

	groupImmut := g

	// 1.AddMember
	err = groupChangeApplicator.ApplyAddMembers(user, inviteLinkPassword, g, submittedActions.AddMembers, groupImmut)
	if err != nil {
		return nil, entities.Status(http.StatusInternalServerError, err.Error())
	}

	mapAddShip := make(map[string]string)
	if submittedActions.AddMembers != nil {
		for _, item := range submittedActions.AddMembers {
			mapAddShip[string(item.Added.UserId)] = user.StrGroupId
		}
	}

	//2.DeleteMembers
	err = groupChangeApplicator.ApplyDeleteMembers(user, inviteLinkPassword, g, submittedActions.DeleteMembers, groupImmut)
	if err != nil {
		return nil, entities.Status(http.StatusInternalServerError, err.Error())
	}

	mapLeaveShip := make(map[string]string)
	if submittedActions.DeleteMembers != nil {
		for _, item := range submittedActions.DeleteMembers {
			mapLeaveShip[string(item.DeletedUserId)] = user.StrGroupId
		}
	}

	//3.ModifyMemberRole
	err = groupChangeApplicator.ApplyModifyMemberRoles(user, inviteLinkPassword, g, submittedActions.ModifyMemberRoles, groupImmut)
	if err != nil {
		return nil, err
	}
	// 4.ModifyMemberProfileKeys
	err = groupChangeApplicator.ApplyModifyMemberProfileKeys(user, inviteLinkPassword, g, submittedActions.ModifyMemberProfileKeys, groupImmut)
	if err != nil {
		return nil, entities.Status(http.StatusInternalServerError, err.Error())
	}

	// 5.AddMembersPendingProfileKey
	err = groupChangeApplicator.ApplyAddMembersPendingProfileKeys(user, inviteLinkPassword, g, submittedActions.AddPendingMembers, groupImmut)
	if err != nil {
		return nil, err
	}

	// 6.DeleteMembersPendingProfileKey
	err = groupChangeApplicator.ApplyDeleteMembersPendingProfileKey(user, inviteLinkPassword, g, submittedActions.DeletePendingMembers, groupImmut)
	if err != nil {
		return nil, err
	}

	// PromoteMembersPendingProfileKey
	err = groupChangeApplicator.ApplyPromoteMembersPendingProfileKey(user, inviteLinkPassword, g, submittedActions.PromotePendingMembers, groupImmut)
	if err != nil {
		return nil, err
	}
	// ModifyTitle
	err = groupChangeApplicator.ApplyModifyTitle(user, inviteLinkPassword, g, submittedActions.ModifyTitle, groupImmut)
	if err != nil {
		return nil, err
	}

	// ModifyAvatar
	err = groupChangeApplicator.ApplyModifyAvatar(user, inviteLinkPassword, g, submittedActions.ModifyAvatar, groupImmut)
	if err != nil {
		return nil, err
	}

	// ModifyDisappearingMessageTimer
	err = groupChangeApplicator.ApplyModifyDisappearingMessageTimer(user, inviteLinkPassword, g, submittedActions.ModifyDisappearingMessagesTimer, groupImmut)
	if err != nil {
		return nil, err
	}
	// ModifyAttributesAccess
	err = groupChangeApplicator.ApplyModifyAttributesAccess(user, inviteLinkPassword, g, submittedActions.ModifyAttributesAccess, groupImmut)
	if err != nil {
		return nil, err
	}
	// ModifyMembersAccess
	err = groupChangeApplicator.ApplyModifyMembersAccess(user, inviteLinkPassword, g, submittedActions.ModifyMemberAccess, groupImmut)
	if err != nil {
		return nil, err
	}
	// ModifyAddFromInviteLinkAccess
	var changeEpoch uint32 = 0
	if submittedActions.ModifyAddFromInviteLinkAccess != nil {
		err = groupChangeApplicator.ApplyModifyAddFromInviteLinkAccess(user, inviteLinkPassword, g, submittedActions.ModifyAddFromInviteLinkAccess, groupImmut)
		if err != nil {
			return nil, err
		}
		changeEpoch = utils.Max(changeEpoch, iNVITE_LINKS_CHANGE_EPOCH)

	}
	// AddMembersPendingAdminApproval
	if len(submittedActions.AddRequestingMembers) > 0 {
		err = groupChangeApplicator.ApplyAddMembersPendingAdminApproval(user, inviteLinkPassword, g, submittedActions.AddRequestingMembers, groupImmut)
		if err != nil {
			return nil, err
		}
		changeEpoch = utils.Max(changeEpoch, iNVITE_LINKS_CHANGE_EPOCH)
	}

	// DeleteMembersPendingAdminApproval
	if len(submittedActions.DeleteRequestingMembers) > 0 {
		err = groupChangeApplicator.ApplyDeleteMembersPendingAdminApproval(user, inviteLinkPassword, g, submittedActions.DeleteRequestingMembers, groupImmut)
		if err != nil {
			return nil, err
		}
		changeEpoch = utils.Max(changeEpoch, iNVITE_LINKS_CHANGE_EPOCH)
	}
	// todo PromotePendingAdminApproval
	if len(submittedActions.PromoteRequestingMembers) > 0 {
		err = groupChangeApplicator.ApplyPromotePendingAdminApproval(user, inviteLinkPassword, g, submittedActions.PromoteRequestingMembers, groupImmut)
		if err != nil {
			return nil, err
		}
		changeEpoch = utils.Max(changeEpoch, iNVITE_LINKS_CHANGE_EPOCH)
	}

	// ModifyInviteLinkPassword
	if submittedActions.ModifyInviteLinkPassword != nil {
		err = groupChangeApplicator.ApplyModifyInviteLinkPassword(user, inviteLinkPassword, g, submittedActions.ModifyInviteLinkPassword, groupImmut)
		if err != nil {
			return nil, err
		}
		changeEpoch = utils.Max(changeEpoch, iNVITE_LINKS_CHANGE_EPOCH)

	}

	// ModifyDescription
	if submittedActions.ModifyDescription != nil {
		err = groupChangeApplicator.ApplyModifyDescription(user, inviteLinkPassword, g, submittedActions.ModifyDescription, groupImmut)
		if err != nil {
			return nil, err
		}
		changeEpoch = utils.Max(changeEpoch, dESCRIPTION_CHANGE_EPOCH)

	}

	// ModifyAnnouncementsOnly
	if submittedActions.ModifyAnnouncementsOnly != nil {
		err = groupChangeApplicator.ApplyModifyAnnouncementsOnly(user, inviteLinkPassword, g, submittedActions.ModifyAnnouncementsOnly, groupImmut)
		if err != nil {
			return nil, err
		}
		changeEpoch = utils.Max(changeEpoch, aNNOUNCEMENTS_ONLY_CHANGE_EPOCH)

	}

	sourceUuid := getSourceUuid(user, g, groupImmut)
	if len(sourceUuid) == 0 {
		return nil, entities.Status(http.StatusForbidden, "SourceUuid is empty")
	}

	submittedActions.SourceUuid = sourceUuid

	bb, err := proto.Marshal(&submittedActions)
	if err != nil {
		return nil, entities.Status(http.StatusInternalServerError, err.Error())
	}
	zkServerSecret, err := zkgroup.GenerateServerSecretParams()
	if err != nil {
		return nil, err
	}
	zkServerSecretParams, err := zkgroup.GenerateServerSecretParamsDeterministic(zkServerSecret)
	if err != nil {
		return nil, err
	}
	signature, err := zkServerSecretParams.Sign(bb)
	if err != nil {
		return nil, entities.Status(http.StatusInternalServerError, err.Error())
	}

	//GroupChange
	signedGroupChange := &signalservice.GroupChange{
		Actions:         bb,
		ServerSignature: signature,
		ChangeEpoch:     changeEpoch,
	}
	//
	g.Revision = submittedActions.Revision
	err = groupValidator.ValidateFinalGroupState(g.DecryptedGroup)
	if err != nil {
		return nil, entities.Status(http.StatusBadRequest, err.Error())
	}

	if err != nil {
		return nil, entities.Status(http.StatusInternalServerError, err.Error())
	}

	saveGroupV2(g.Hexid)
	return &entities.Resp{Obj: signedGroupChange}, nil
}

func getSourceUuid(user *entities.GroupUser, group *GroupV2, groupImmut *GroupV2) []byte {
	var sourceUuid []byte

	if item := GetSourceMember(user, groupImmut); item != nil {
		sourceUuid = item.Uuid
	}
	if len(sourceUuid) != 0 {
		return sourceUuid
	}

	if item := GetSourceMember(user, group); item != nil {
		sourceUuid = item.Uuid
	}
	if len(sourceUuid) != 0 {
		return sourceUuid
	}
	//-------------------------

	if item := GetMemberPendingProfileKey(user, groupImmut); item != nil {
		sourceUuid = item.Uuid
	}
	if len(sourceUuid) != 0 {
		return sourceUuid
	}

	if item := GetMemberPendingAdminApproval(user, groupImmut); item != nil {
		sourceUuid = item.Uuid
	}
	if len(sourceUuid) != 0 {
		return sourceUuid
	}

	if item := GetMemberPendingAdminApproval(user, group); item != nil {
		sourceUuid = item.Uuid
	}
	if len(sourceUuid) != 0 {
		return sourceUuid
	}

	return sourceUuid

}
