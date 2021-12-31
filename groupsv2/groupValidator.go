package groupsv2

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/nanu-c/zkgroup"
	"github.com/signal-golang/textsecure/config"
	"github.com/signal-golang/textsecure/entities"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	"github.com/signal-golang/textsecure/utils"
	log "github.com/sirupsen/logrus"
)

var INVITE_LINK_PASSWORD_SIZE_BYTES = 16

type GroupValidator struct {
	profileOperations              *zkgroup.ServerZkProfileOperations
	maxGroupSize                   int
	maxGroupTitleLengthBytes       int
	maxGroupDescriptionLengthBytes int
}

func NewGroupValidator(profileOp *zkgroup.ServerZkProfileOperations, config *config.Config) *GroupValidator {
	return &GroupValidator{
		profileOperations:              profileOp,
		maxGroupSize:                   config.Group.MaxGroupSize,
		maxGroupTitleLengthBytes:       config.Group.MaxGroupTitleLengthBytes,
		maxGroupDescriptionLengthBytes: config.Group.MaxGroupTitleLengthBytes,
	}
}

func (g *GroupValidator) ValidatePresentationUpdate(source *entities.GroupUser,
	group *GroupV2,
	presentationData []byte) (zkgroup.ProfileKeyCredentialPresentation, error) {

	var publicParams zkgroup.GroupPublicParams = group.MasterKey
	if len(presentationData) == 0 {
		return nil, errors.New("ValidatePresentationUpdate 1.  presentationData is empty")
	}
	presentation, err := zkgroup.NewProfileKeyCredentialPresentation(presentationData)
	if err != nil {
		return nil, errors.New("ValidatePresentationUpdate 2.  " + err.Error())
	}
	presentation_uuid, err := presentation.UUIDCiphertext()
	if err != nil {
		return nil, errors.New("ValidatePresentationUpdate 3.  " + err.Error())
	}
	_, err = presentation.ProfileKeyCiphertext()
	if err != nil {
		return nil, errors.New("ValidatePresentationUpdate 3.1.  " + err.Error())
	}
	if !source.IsMember(presentation_uuid, group.MasterKey) {
		return nil, errors.New("ValidatePresentationUpdate 4.Forbidden ,reason:xxx ")
	}
	err = g.profileOperations.VerifyProfileKeyCredentialPresentation(publicParams, presentation)
	if err != nil {
		return nil, errors.New("ValidatePresentationUpdate 5.  " + err.Error())
	}
	return presentation, nil

}
func (g *GroupValidator) ValidateAccessControl(group *signalservice.DecryptedGroup) error {

	accessControl := group.AccessControl
	list := []signalservice.AccessControl_AccessRequired{signalservice.AccessControl_MEMBER, signalservice.AccessControl_UNKNOWN, signalservice.AccessControl_ADMINISTRATOR}
	if !IsAccessRequiredOneOf(accessControl.Attributes, list...) {
		return errors.New("attribute access invalid")
	}

	if !IsAccessRequiredOneOf(accessControl.Members, list...) {
		return errors.New("attribute access invalid")
	}

	if !IsAccessRequiredOneOf(accessControl.AddFromInviteLink, append(list, signalservice.AccessControl_ANY, signalservice.AccessControl_UNSATISFIABLE)...) {
		return errors.New("add from invite link access invalid")
	}

	return nil
}

func (g *GroupValidator) ValidateRoles(group *signalservice.DecryptedGroup) error {
	for _, item := range group.Members {
		if item.Role != signalservice.Member_DEFAULT && item.Role != signalservice.Member_ADMINISTRATOR {
			return errors.New("invalid member role ")
		}
	}

	for _, item := range group.PendingMembers {
		if item.Role != signalservice.Member_DEFAULT && item.Role != signalservice.Member_ADMINISTRATOR {
			return errors.New("invalid member role ")
		}
	}

	return nil
}

func (g *GroupValidator) ValidateFinalGroupState(group *signalservice.DecryptedGroup) error {
	if len(group.GetTitle()) == 0 {
		return errors.New("group title must be non-empty")
	}

	if len(group.GetTitle()) > g.maxGroupTitleLengthBytes {
		return errors.New("group title length exceeded")
	}
	if len(group.GetDescription()) > g.maxGroupDescriptionLengthBytes {
		return errors.New("group description length exceeded")
	}
	/*
		if len(group.GetInviteLinkPassword())!=0 && len(group.GetInviteLinkPassword()) != INVITE_LINK_PASSWORD_SIZE_BYTES {
			return errors.New("group invite link password cannot be set to invalid size")
		}
	*/
	if len(group.GetInviteLinkPassword()) == 0 &&
		group.GetAccessControl().GetAddFromInviteLink() != signalservice.AccessControl_UNSATISFIABLE &&
		group.GetAccessControl().GetAddFromInviteLink() != signalservice.AccessControl_UNKNOWN {
		return errors.New("group cannot permit joining with no password")
	}

	// the admin approval pending list was purposefully left out of this computation

	if len(group.PendingMembers)+len(group.Members) > g.maxGroupSize {
		return errors.New("group size cannot exceed " + fmt.Sprintf("%d", g.maxGroupSize))
	}
	// put some sort of cap on the maximum number of accounts that can be pending admin review
	if len(group.RequestingMembers) > g.maxGroupSize {
		return errors.New("members pending admin approval cannot exceed " + fmt.Sprintf("%d", g.maxGroupSize))
	}
	mapUserIds := make(map[string]struct{})
	mapPendingProfileKeyUserIds := make(map[string]struct{})
	mapPendingAdminApprovalUserIds := make(map[string]struct{})

	for _, item := range group.Members {
		mapUserIds[base64.StdEncoding.EncodeToString(item.Uuid)] = struct{}{}
	}

	for _, item := range group.PendingMembers {
		mapPendingProfileKeyUserIds[base64.StdEncoding.EncodeToString(item.Uuid)] = struct{}{}
	}

	for _, item := range group.RequestingMembers {
		mapPendingAdminApprovalUserIds[base64.StdEncoding.EncodeToString(item.Uuid)] = struct{}{}
	}
	if len(mapUserIds) != len(group.Members) ||
		len(mapPendingProfileKeyUserIds) != len(group.PendingMembers) ||
		len(mapPendingAdminApprovalUserIds) != len(group.RequestingMembers) {
		return errors.New("group cannot contain duplicate user ids in the membership lists")
	}

	for k := range mapUserIds {
		if _, ok := mapPendingProfileKeyUserIds[k]; ok {
			return errors.New("group cannot contain the same user in multiple membership lists(members pendingprofilekey)")
		}
		if _, ok := mapPendingAdminApprovalUserIds[k]; ok {
			return errors.New("group cannot contain the same user in multiple membership lists(members PendingAdminApproval)")
		}
	}
	for k := range mapPendingAdminApprovalUserIds {
		if _, ok := mapPendingProfileKeyUserIds[k]; ok {
			return errors.New("group cannot contain the same user in multiple membership lists(pendingprofilekey,PendingAdminApproval)")
		}

	}
	err := g.ValidateRoles(group)
	if err != nil {
		return err
	}

	return g.ValidateAccessControl(group)

}

func (g *GroupValidator) ValidateAddMembersPendingAdminApproval(user *entities.GroupUser, inviteLinkPassword []byte,
	group *GroupV2, actions []*signalservice.GroupChange_Actions_AddRequestingMemberAction) error {
	if len(actions) == 0 {
		return nil
	}
	if !bytes.Equal(inviteLinkPassword, group.DecryptedGroup.GetInviteLinkPassword()) {
		return errors.New("inviteLinkPassword error,forbidden")
	}
	for _, action := range actions {
		if action.Added == nil {
			return errors.New("missing added field in add members pending admin approval actions")
		}
		newAdd, err := g.ValidateMemberPendingAdminApproval(user, group, action.Added)
		if err != nil {
			return err
		}
		action.Added = newAdd
	}
	return nil

}

func (g *GroupValidator) ValidateMemberPendingAdminApproval(user *entities.GroupUser, group *GroupV2,
	memberPendingAdminApproval *signalservice.RequestingMember) (*signalservice.RequestingMember, error) {
	if len(memberPendingAdminApproval.UserId) != 0 {
		return nil, errors.New("user id should not be set in request")
	}

	if len(memberPendingAdminApproval.ProfileKey) != 0 {
		return nil, errors.New("profile key should not be set in request")
	}

	if len(memberPendingAdminApproval.Presentation) == 0 {
		return nil, errors.New("missing presentation in request")
	}

	if memberPendingAdminApproval.Timestamp != 0 {
		return nil, errors.New("timestamp should not be set in request")
	}
	var publicParams zkgroup.GroupPublicParams = group.MasterKey
	profileKeyCredentialPresentation, err := zkgroup.NewProfileKeyCredentialPresentation(memberPendingAdminApproval.Presentation)
	if err != nil {
		return nil, errors.New("1." + err.Error())
	}

	err = g.profileOperations.VerifyProfileKeyCredentialPresentation(publicParams, profileKeyCredentialPresentation)
	if err != nil {
		log.Errorln("[textsecure] groupsv2-validator 2.", err)
		return nil, errors.New("2." + err.Error())
	}
	b, err := profileKeyCredentialPresentation.UUIDCiphertext()
	if err != nil {
		log.Errorln("[textsecure] groupsv2-validator 3.", err)
		return nil, errors.New("3." + err.Error())
	}

	if !user.IsMember(b, group.MasterKey) {
		return nil, errors.New("cannot add others to a group using an invite link")
	}

	bb, err := profileKeyCredentialPresentation.ProfileKeyCiphertext()
	if err != nil {
		log.Errorln("[textsecure] groupsv2-validator 4.", err)
		return nil, errors.New("4." + err.Error())
	}

	memberPendingAdminApproval.ProfileKey = bb
	memberPendingAdminApproval.UserId = b
	memberPendingAdminApproval.Timestamp = uint64(utils.CurrentTimeMillis())

	return memberPendingAdminApproval, nil
}

func (g *GroupValidator) ValidateMemberPendingProfileKey(group *GroupV2, member *signalservice.DecryptedMember,
	memberPendingProfileKey *signalservice.PendingMember) (*signalservice.PendingMember, error) {
	if memberPendingProfileKey.GetMember() == nil {
		return nil, errors.New("1.missing member")
	}
	if len(memberPendingProfileKey.GetMember().GetUserId()) == 0 {
		return nil, errors.New("2.missing member user id")
	}

	if memberPendingProfileKey.GetMember().GetRole() == signalservice.Member_UNKNOWN {
		return nil, errors.New("3.unknown member role")
	}
	if len(memberPendingProfileKey.GetMember().GetPresentation()) != 0 {
		return nil, errors.New("4.There's a presentation for a pending member")
	}

	if len(memberPendingProfileKey.GetMember().GetProfileKey()) != 0 {
		return nil, errors.New("5.There's a profile key for a pending member")
	}
	memberPendingProfileKey.GetMember().ProfileKey = nil
	memberPendingProfileKey.GetMember().Presentation = nil
	memberPendingProfileKey.GetMember().JoinedAtRevision = group.Revision

	memberPendingProfileKey.AddedByUserId = member.GetUuid()
	memberPendingProfileKey.Timestamp = uint64(utils.CurrentTimeMillis())

	return memberPendingProfileKey, nil

}

func (g *GroupValidator) ValidateAddMembersPendingProfileKey(user *entities.GroupUser,
	group *GroupV2, actions []*signalservice.GroupChange_Actions_AddPendingMemberAction) error {
	if len(actions) == 0 {
		return nil
	}
	addedBy := GetSourceMember(user, group)
	if addedBy == nil {
		return errors.New("forbidden")
	}

	for _, action := range actions {
		if action.Added == nil || action.Added.Member == nil {
			return errors.New("Bad member construction!")
		}
		newPK, err := g.ValidateMemberPendingProfileKey(group, addedBy, action.Added)
		if err != nil {
			return err
		}
		action.Added = newPK
	}

	return nil

}

func (g *GroupValidator) ValidateAddMember(user *entities.GroupUser, inviteLinkPassword []byte,
	group *GroupV2, actions []*signalservice.GroupChange_Actions_AddMemberAction, groupPublicKey []byte) error {
	if len(actions) == 0 {
		return nil
	}

	for _, action := range actions {
		if action.Added == nil || len(action.Added.Presentation) == 0 {
			return errors.New("Bad member construction")
		}
		if action.JoinFromInviteLink {
			return errors.New("Invalid field set on action")
		}
		newAdd, err := g.ValidateMember(group, action.Added, group.MasterKey) //从加密的内容解析一些数据
		if err != nil {
			return err
		}
		action.Added = newAdd
		if !IsMember(user, group) &&
			user.IsMember(newAdd.UserId, groupPublicKey) &&
			group.DecryptedGroup.AccessControl.Members != signalservice.AccessControl_ANY &&
			group.DecryptedGroup.AccessControl.AddFromInviteLink == signalservice.AccessControl_ANY &&
			bytes.Equal(group.DecryptedGroup.InviteLinkPassword, inviteLinkPassword) {
			action.JoinFromInviteLink = true
		}
	}

	return nil

}

func (g *GroupValidator) ValidateMember(group *GroupV2, member *signalservice.Member, publicKey []byte) (*signalservice.Member, error) {
	if member.GetRole() == signalservice.Member_UNKNOWN {
		log.Errorln("[textsecure] groupsv2-validator 1.Unknown member role")
		return nil, errors.New("1.Unknown member role")
	}
	if member.GetPresentation() == nil || len(member.GetPresentation()) == 0 {
		log.Errorln("[textsecure] groupsv2-validator 2.Missing presentation")
		return nil, errors.New("2.Missing presentation")
	}
	var publicParams zkgroup.GroupPublicParams = publicKey
	profileKeyCredentialPresentation, err := zkgroup.NewProfileKeyCredentialPresentation(member.Presentation)
	if err != nil {
		log.Errorln("[textsecure] groupsv2-validator 3.", err)
		return nil, errors.New("3." + err.Error())
	}
	err = g.profileOperations.VerifyProfileKeyCredentialPresentation(publicParams, profileKeyCredentialPresentation)
	if err != nil {
		log.Errorln("[textsecure] groupsv2-validator 4.", err)
		return nil, errors.New("4." + err.Error())
	}
	member.ProfileKey, err = profileKeyCredentialPresentation.ProfileKeyCiphertext()
	if err != nil {
		log.Errorln("[textsecure] groupsv2-validator 5.", err)
		return nil, errors.New("5." + err.Error())
	}

	member.UserId, err = profileKeyCredentialPresentation.UUIDCiphertext() //替换到了
	if err != nil {
		log.Errorln("[textsecure] groupsv2-validator 6.", err)
		return nil, errors.New("6." + err.Error())
	}

	userUUid, err := utils.UUIDStr(member.UserId)
	if err != nil {
		log.Errorln("[textsecure] groupsv2-validator 7.", err)
		return nil, errors.New("7." + err.Error())
	}
	member.UserId = []byte(userUUid)
	member.JoinedAtRevision = group.Revision
	member.Presentation = nil //todo
	return member, nil

}

func (g *GroupValidator) IsValidAvatarUrl(url string, groupId []byte) bool {
	return true
	if len(url) == 0 {
		return true
	}
	prefix := `groups/` + base64.URLEncoding.EncodeToString(groupId) + `/`
	if !strings.HasPrefix(url, prefix) {
		return false
	}

	parts := strings.Split(url, `/`)
	if len(parts) != 3 {
		return false
	}
	b, _ := base64.StdEncoding.DecodeString(parts[2])
	return len(b) == 16

}
