package groupsv2

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/nanu-c/zkgroup"
	"github.com/signal-golang/textsecure/entities"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	"github.com/signal-golang/textsecure/utils"
)

func getKey(userId []byte) string {
	return base64.StdEncoding.EncodeToString(userId)
}

type GroupChangeApplicator struct {
	groupValidator *GroupValidator
}

func NewGroupChangeApplicator(g *GroupValidator) *GroupChangeApplicator {
	return &GroupChangeApplicator{
		groupValidator: g,
	}
}

func (g *GroupChangeApplicator) ApplyModifyAnnouncementsOnly(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	action *signalservice.GroupChange_Actions_ModifyAnnouncementsOnlyAction, groupImmut *GroupV2) error {

	if !isModifyAnnouncementsOnlyAllowed(user, groupImmut) {
		return entities.Status(http.StatusForbidden, "!isModifyAnnouncementsOnlyAllowed")
	}
	group.AnnouncementsOnly = action.AnnouncementsOnly

	return nil
}

func (g *GroupChangeApplicator) ApplyModifyDescription(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	action *signalservice.GroupChange_Actions_ModifyDescriptionAction, groupImmut *GroupV2) error {

	if !isModifyAttributesAllowed(user, groupImmut) {
		return entities.Status(http.StatusForbidden, "!isModifyAttributesAllowed")
	}
	// todo byte to string
	group.DecryptedGroup.Description = string(action.Description[:])

	return nil
}

func (g *GroupChangeApplicator) ApplyModifyInviteLinkPassword(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	action *signalservice.GroupChange_Actions_ModifyInviteLinkPasswordAction, groupImmut *GroupV2) error {
	if !isModifyInviteLinkPasswordAllowed(user, groupImmut) {
		return entities.Status(http.StatusForbidden, "!isModifyInviteLinkPasswordAllowed")
	}
	group.DecryptedGroup.InviteLinkPassword = action.InviteLinkPassword

	return nil
}

func (g *GroupChangeApplicator) ApplyPromotePendingAdminApproval(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	actions []*signalservice.GroupChange_Actions_PromoteRequestingMemberAction, groupImmut *GroupV2) error {

	if actions == nil {
		return nil
	}
	if !isPromoteMembersPendingAdminApprovalAllowed(user, groupImmut) {
		return entities.Status(http.StatusForbidden, "!isPromoteMembersPendingAdminApprovalAllowed")
	}
	// PendingAdminProvalUserId
	mapPendingAdminProvalUserId := make(map[string][]byte)
	for _, item := range group.DecryptedGroup.RequestingMembers {
		mapPendingAdminProvalUserId[getKey(item.Uuid)] = item.ProfileKey
	}

	mapMember := make(map[string]struct{})
	for _, item := range group.DecryptedGroup.Members {
		mapMember[getKey(item.Uuid)] = struct{}{}
	}

	mapModifyUserId := make(map[string]signalservice.Member_Role)
	for _, item := range actions {
		if item == nil {
			return entities.Status(http.StatusBadRequest, "nil ptr in request")
		}
		key := getKey(item.UserId)

		if _, ok := mapModifyUserId[key]; ok {
			return entities.Status(http.StatusBadRequest, "duplicate user ids in request")
		}

		if _, ok := mapMember[key]; ok {
			return entities.Status(http.StatusBadRequest, "some user ids already in members")
		}
		// PendingAdminProvalUserId
		var v []byte
		v, ok := mapPendingAdminProvalUserId[key]
		if !ok {
			return entities.Status(http.StatusBadRequest, "some user ids were not in the set of members pending admin approval")
		}
		mapModifyUserId[key] = item.Role

		group.DecryptedGroup.Members = append(group.DecryptedGroup.Members, &signalservice.DecryptedMember{
			Uuid:             item.UserId,
			Role:             item.Role,
			JoinedAtRevision: group.Revision + 1,
			ProfileKey:       v,
		})
	}
	var ship []*signalservice.DecryptedRequestingMember
	for _, item := range group.DecryptedGroup.RequestingMembers {
		if _, ok := mapModifyUserId[getKey(item.Uuid)]; !ok {
			ship = append(ship, item)
		}
	}
	group.DecryptedGroup.RequestingMembers = ship

	return nil
}

func (g *GroupChangeApplicator) ApplyDeleteMembersPendingAdminApproval(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	actions []*signalservice.GroupChange_Actions_DeleteRequestingMemberAction, groupImmut *GroupV2) error {

	if actions == nil {
		return nil
	}
	if !isDeleteMembersPendingAdminApprovalAllowed(user, groupImmut, actions) {
		return entities.Status(http.StatusForbidden, "!isDeleteMembersPendingAdminApprovalAllowed")
	}
	mapModifyUserId := make(map[string]struct{})
	for _, item := range actions {
		if actions == nil {
			return entities.Status(http.StatusBadRequest, "nil ptr in request")
		}
		key := getKey(item.DeletedUserId)
		if _, ok := mapModifyUserId[key]; ok {
			return entities.Status(http.StatusBadRequest, "duplicate user ids in request")
		}
		mapModifyUserId[key] = struct{}{}
	}

	mapPendingAdminProvalUserId := make(map[string]struct{})
	for _, item := range group.DecryptedGroup.RequestingMembers {
		mapPendingAdminProvalUserId[getKey(item.Uuid)] = struct{}{}
	}

	for key, _ := range mapModifyUserId {
		if _, ok := mapPendingAdminProvalUserId[key]; !ok {
			return entities.Status(http.StatusBadRequest, "some user ids not pending admin approval")
		}
	}

	var ship []*signalservice.DecryptedRequestingMember
	for _, item := range group.DecryptedGroup.RequestingMembers {
		if _, ok := mapModifyUserId[getKey(item.Uuid)]; !ok {
			ship = append(ship, item)
		}
	}
	group.DecryptedGroup.RequestingMembers = ship

	return nil
}

func (g *GroupChangeApplicator) ApplyAddMembersPendingAdminApproval(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	actions []*signalservice.GroupChange_Actions_AddRequestingMemberAction, groupImmut *GroupV2) error {

	if actions == nil {
		return nil
	}
	if !isAddMembersPendingAdminApprovalAllowed(user, inviteLinkPassword, groupImmut) {
		return entities.Status(http.StatusForbidden, "!isAddMembersPendingAdminApprovalAllowed")
	}
	mapModifyUserId := make(map[string]struct{})
	for _, item := range actions {
		if actions == nil {
			return entities.Status(http.StatusBadRequest, "nil ptr in request")
		}
		key := getKey(item.Added.UserId)
		if _, ok := mapModifyUserId[key]; ok {
			return entities.Status(http.StatusBadRequest, "duplicate user ids in request")
		}
		mapModifyUserId[key] = struct{}{}
	}

	mapUserId := make(map[string]struct{})
	for _, item := range group.DecryptedGroup.Members {
		mapUserId[getKey(item.Uuid)] = struct{}{}
	}

	mapPendingProfileUserId := make(map[string]struct{})
	for _, item := range group.DecryptedGroup.PendingMembers {
		mapPendingProfileUserId[getKey(item.Uuid)] = struct{}{}
	}

	mapPendingAdminProvalUserId := make(map[string]struct{})
	for _, item := range group.DecryptedGroup.RequestingMembers {
		mapPendingAdminProvalUserId[getKey(item.Uuid)] = struct{}{}
	}

	for key, _ := range mapModifyUserId {
		if _, ok := mapUserId[key]; ok {
			return entities.Status(http.StatusBadRequest, " cannot ask to join via invite link if already in group")
		}
		if _, ok := mapPendingProfileUserId[key]; ok {
			return entities.Status(http.StatusBadRequest, " cannot ask to join via invite link if already in group pending profile key")
		}

		if _, ok := mapPendingAdminProvalUserId[key]; ok {
			return entities.Status(http.StatusBadRequest, " cannot ask to join via invite link if already asked to join")
		}
	}

	if len(actions) != 1 || !user.IsMember(actions[0].Added.UserId, group.MasterKey) {
		return entities.Status(http.StatusBadRequest, "request contains non-self user ids")
	}
	for _, item := range actions {
		group.GroupContext.RequestingMembers = append(group.GroupContext.RequestingMembers, item.Added)
	}

	return nil
}

func (g *GroupChangeApplicator) ApplyModifyAddFromInviteLinkAccess(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	action *signalservice.GroupChange_Actions_ModifyAddFromInviteLinkAccessControlAction, groupImmut *GroupV2) error {

	if action == nil {
		return nil
	}
	if !isModifyAddFromInviteLinkAccessControlAllowe(user, groupImmut) {
		return entities.Status(http.StatusForbidden, "!isModifyAddFromInviteLinkAccessControlAllowe")
	}

	if action.AddFromInviteLinkAccess != signalservice.AccessControl_ADMINISTRATOR &&
		action.AddFromInviteLinkAccess != signalservice.AccessControl_UNSATISFIABLE &&
		action.AddFromInviteLinkAccess != signalservice.AccessControl_ANY {
		return entities.Status(http.StatusBadRequest, "  action.AddFromInviteLinkAccess invalid")
	}

	group.DecryptedGroup.AccessControl.AddFromInviteLink = action.AddFromInviteLinkAccess

	return nil
}

func (g *GroupChangeApplicator) ApplyModifyMembersAccess(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	modifyMembersAccess *signalservice.GroupChange_Actions_ModifyMembersAccessControlAction, groupImmut *GroupV2) error {

	if modifyMembersAccess == nil {
		return nil
	}
	if modifyMembersAccess.MembersAccess != signalservice.AccessControl_ADMINISTRATOR &&
		modifyMembersAccess.MembersAccess != signalservice.AccessControl_MEMBER {
		return entities.Status(http.StatusBadRequest, "  modifyMemberAccess.AttributesAccess invalid")
	}

	if !isAdminstrator(user, groupImmut) {
		return entities.Status(http.StatusForbidden, "isAdminstrator(user,group)")
	}
	group.DecryptedGroup.AccessControl.Members = modifyMembersAccess.MembersAccess

	return nil
}

func (g *GroupChangeApplicator) ApplyModifyAttributesAccess(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	modifyAttributesAccess *signalservice.GroupChange_Actions_ModifyAttributesAccessControlAction, groupImmut *GroupV2) error {

	if modifyAttributesAccess == nil {
		return nil
	}
	if modifyAttributesAccess.AttributesAccess != signalservice.AccessControl_ADMINISTRATOR &&
		modifyAttributesAccess.AttributesAccess != signalservice.AccessControl_MEMBER {
		return entities.Status(http.StatusBadRequest, "  modifyAttributesAccess.AttributesAccess invalid")
	}

	if !isAdminstrator(user, groupImmut) {
		return entities.Status(http.StatusForbidden, "isAdminstrator(user,group)")
	}
	group.DecryptedGroup.AccessControl.Attributes = modifyAttributesAccess.AttributesAccess

	return nil
}

func (g *GroupChangeApplicator) ApplyModifyDisappearingMessageTimer(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	modifyDisappearingMessageTimer *signalservice.GroupChange_Actions_ModifyDisappearingMessagesTimerAction, groupImmut *GroupV2) error {
	if modifyDisappearingMessageTimer == nil {
		return nil
	}

	if !isModifyAttributesAllowed(user, groupImmut) {
		return entities.Status(http.StatusForbidden, "forbidden by  !isModifyAttributesAllowed")
	}
	// todo decrypt message timer
	// group.DecryptedGroup.DisappearingMessagesTimer = modifyDisappearingMessageTimer.Timer

	return nil
}

func (g *GroupChangeApplicator) ApplyModifyAvatar(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	modifyAvatar *signalservice.GroupChange_Actions_ModifyAvatarAction, groupImmut *GroupV2) error {
	if modifyAvatar == nil {
		return nil
	}
	/*
		if len(modifyAvatar.Avatar)==0{
			return entities.Status(http.StatusBadRequest," modifyAvatar is not empty")
		}*/

	if !isModifyAttributesAllowed(user, groupImmut) {
		return entities.Status(http.StatusForbidden, "forbidden by  !isModifyAttributesAllowed")
	}

	if !g.groupValidator.IsValidAvatarUrl(modifyAvatar.Avatar, user.GroupId) {
		return entities.Status(http.StatusBadRequest, "avatar format error")
	}

	group.DecryptedGroup.Avatar = modifyAvatar.Avatar

	return nil
}

func (g *GroupChangeApplicator) ApplyModifyTitle(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	modifyTitle *signalservice.GroupChange_Actions_ModifyTitleAction, groupImmut *GroupV2) error {
	if modifyTitle == nil {
		return nil
	}
	if len(modifyTitle.Title) == 0 {
		return entities.Status(http.StatusBadRequest, " modifyTitle is not empty")
	}
	if !isModifyAttributesAllowed(user, groupImmut) {
		return entities.Status(http.StatusForbidden, "forbidden by  !isModifyAttributesAllowed")
	}
	//todo decrypt title
	group.DecryptedGroup.Title = string(modifyTitle.Title[:])

	return nil
}

func (g *GroupChangeApplicator) ApplyPromoteMembersPendingProfileKey(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	promoteMembersPendingProfileKeys []*signalservice.GroupChange_Actions_PromotePendingMemberAction, groupImmut *GroupV2) error {
	if len(promoteMembersPendingProfileKeys) == 0 {
		return nil
	}
	var presentations []zkgroup.ProfileKeyCredentialPresentation
	for _, item := range promoteMembersPendingProfileKeys {
		presentation, err := g.groupValidator.ValidatePresentationUpdate(user, groupImmut, item.Presentation)
		if err != nil {
			return entities.Status(http.StatusInternalServerError, err.Error())
		}
		presentations = append(presentations, presentation)
	}

	mapUserId := make(map[string]struct{})
	for _, item := range group.DecryptedGroup.PendingMembers {
		mapUserId[getKey(item.Uuid)] = struct{}{}
	}

	mapModifyUserId := make(map[string][]byte)
	for _, item := range presentations {
		uuid_cipher, _ := item.UUIDCiphertext()
		k := getKey(uuid_cipher)
		if _, ok := mapModifyUserId[k]; ok {
			return entities.Status(http.StatusBadRequest, "ApplyPromoteMembersPendingProfileKey:1-> duplicates userID")
		}
		if _, ok := mapUserId[k]; !ok {
			return entities.Status(http.StatusBadRequest, "invaild pendingprofile user")
		}
		profileKeyCiphertext, _ := item.ProfileKeyCiphertext()
		mapModifyUserId[k] = profileKeyCiphertext
	}
	for _, item := range group.GroupContext.PendingMembers {
		key := getKey(item.Member.UserId)
		if value, ok := mapModifyUserId[key]; ok {
			item.Member.Presentation = nil
			item.Member.ProfileKey = value
			item.Member.JoinedAtRevision = group.Revision + 1
		}
	}

	return nil
}

func (g *GroupChangeApplicator) ApplyDeleteMembersPendingProfileKey(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	deleteMembersPendingProfileKeys []*signalservice.GroupChange_Actions_DeletePendingMemberAction, groupImmut *GroupV2) error {

	if len(deleteMembersPendingProfileKeys) == 0 {
		return nil
	}

	if !isDeleteMembersPendingProfileKeyAllowed(user, groupImmut, deleteMembersPendingProfileKeys) {
		return entities.Status(http.StatusForbidden, "[ApplyDeleteMembersPendingProfileKey] !isDeleteMembersPendingProfileKeyAllowed")
	}

	mapModifyUserId := make(map[string]struct{})
	for _, item := range deleteMembersPendingProfileKeys {
		key := getKey(item.DeletedUserId)
		if _, ok := mapModifyUserId[key]; ok {
			return entities.Status(http.StatusBadRequest, "[ApplyDeleteMembersPendingProfileKey] Duplicatates userId")
		}
		mapModifyUserId[key] = struct{}{}
	}

	mapUserId := make(map[string]struct{})
	for _, item := range group.DecryptedGroup.PendingMembers {
		mapUserId[getKey(item.Uuid)] = struct{}{}
	}
	for k := range mapModifyUserId {
		if _, ok := mapUserId[k]; !ok {
			return entities.Status(http.StatusBadRequest, "[ApplyDeleteMembersPendingProfileKey] userId not exist roup.MembersPendingProfileKey")
		}
	}
	var memberShip []*signalservice.DecryptedPendingMember
	for _, item := range group.DecryptedGroup.PendingMembers {
		key := getKey(item.Uuid)
		if _, ok := mapModifyUserId[key]; !ok {
			memberShip = append(memberShip, item)
		}
	}
	group.DecryptedGroup.PendingMembers = memberShip

	return nil
}

func (g *GroupChangeApplicator) ApplyAddMembersPendingProfileKeys(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	addMembersPendingProfileKeys []*signalservice.GroupChange_Actions_AddPendingMemberAction, groupImmut *GroupV2) error {

	if len(addMembersPendingProfileKeys) == 0 {
		return nil
	}
	if !isAddMembersPendingProfileKeyAllowed(user, groupImmut) {
		return entities.Status(http.StatusForbidden, "!isAddMembersPendingProfileKeyAllowed(user,group)")
	}
	mapAddUserId := make(map[string]struct{})
	for _, item := range addMembersPendingProfileKeys {
		if item.Added.Member == nil {
			return entities.Status(http.StatusBadRequest, "No member")
		}
		if len(item.Added.Member.UserId) == 0 {
			return entities.Status(http.StatusBadRequest, "No user id")
		}
		if len(item.Added.Member.ProfileKey) == 0 {
			return entities.Status(http.StatusBadRequest, "Profile key present for invitation")
		}
		if len(item.Added.Member.Presentation) == 0 {
			return entities.Status(http.StatusBadRequest, "Presentation not empty for invitation")
		}
		if item.Added.Member.Role == signalservice.Member_UNKNOWN {
			return entities.Status(http.StatusBadRequest, "role is unknown")
		}
		if item.Added.Member.Role == signalservice.Member_ADMINISTRATOR && !isAdminstrator(user, groupImmut) {
			return entities.Status(http.StatusForbidden, "MembersPendingProfileKey user role is admin ,but he is not group admin  +"+user.StrUserUUId)
		}
		key := getKey(item.Added.Member.UserId)
		if _, ok := mapAddUserId[key]; ok {
			return entities.Status(http.StatusBadRequest, "userId duplicate")
		}
		mapAddUserId[key] = struct{}{}
	}

	mapUserUsrId := make(map[string]struct{})
	for _, member := range group.DecryptedGroup.Members {
		mapUserUsrId[getKey(member.Uuid)] = struct{}{}
	}
	for _, member := range group.DecryptedGroup.PendingMembers {
		mapUserUsrId[getKey(member.Uuid)] = struct{}{}
	}
	//去重
	for k := range mapAddUserId {
		if _, ok := mapUserUsrId[k]; ok {
			return entities.Status(http.StatusBadRequest, "Member is already present")
		}
	}

	for _, item := range addMembersPendingProfileKeys {
		obj := &signalservice.DecryptedPendingMember{
			Role:        item.Added.Member.Role,
			Uuid:        item.Added.Member.UserId,
			AddedByUuid: GetSourceMember(user, group).Uuid, //todo
			Timestamp:   uint64(utils.CurrentTimeMillis()),
		}
		group.DecryptedGroup.PendingMembers = append(group.DecryptedGroup.PendingMembers, obj)
	}

	return nil
}

func (g *GroupChangeApplicator) ApplyModifyMemberProfileKeys(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	modifyMembers []*signalservice.GroupChange_Actions_ModifyMemberProfileKeyAction, groupImmut *GroupV2) error {
	if len(modifyMembers) == 0 {
		return nil
	}
	var presentations []zkgroup.ProfileKeyCredentialPresentation
	for _, item := range modifyMembers {
		presentation, err := g.groupValidator.ValidatePresentationUpdate(user, groupImmut, item.Presentation)
		if err != nil {
			return err
		}
		presentations = append(presentations, presentation)
	}
	//去从
	mapModifyUserId := make(map[string][]byte)
	for _, item := range presentations {
		uuid_cipher, _ := item.UUIDCiphertext()
		k := getKey(uuid_cipher)
		if _, ok := mapModifyUserId[k]; ok {
			return errors.New("ApplyModifyMemberProfileKeys:1-> duplicates userID")
		}
		profileKeyCiphertext, _ := item.ProfileKeyCiphertext()
		mapModifyUserId[k] = profileKeyCiphertext
	}
	for _, member := range group.DecryptedGroup.Members {
		key := getKey(member.Uuid)
		if value, ok := mapModifyUserId[key]; ok {
			member.ProfileKey = value
		}
	}

	return nil
}

func (g *GroupChangeApplicator) ApplyModifyMemberRoles(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	modifyMembers []*signalservice.GroupChange_Actions_ModifyMemberRoleAction, groupImmut *GroupV2) error {
	// 1
	if len(modifyMembers) == 0 {
		return nil
	}
	if !isAdminstrator(user, groupImmut) {
		return entities.Status(http.StatusBadRequest, "not admin , Forbidden")
	}

	mapUserId := make(map[string]*signalservice.DecryptedMember)
	for _, member := range group.DecryptedGroup.Members {
		mapUserId[getKey(member.Uuid)] = member
	}

	mapModifyUserID := make(map[string]*signalservice.GroupChange_Actions_ModifyMemberRoleAction)
	for _, member := range modifyMembers {

		if len(member.UserId) == 0 {
			return entities.Status(http.StatusBadRequest, "1->BadRequest userID is empty")
		}

		if member.Role == signalservice.Member_UNKNOWN {
			return entities.Status(http.StatusBadRequest, "2->BadRequest role is unknown")
		}

		key := getKey(member.UserId)
		if _, ok := mapModifyUserID[key]; ok {

			return entities.Status(http.StatusBadRequest, "3->BadRequest Duplicate member userID")
		}
		if _, ok := mapUserId[key]; !ok {
			return entities.Status(http.StatusBadRequest, "not this member")
		}
		mapModifyUserID[key] = member //map

	}

	for _, item := range mapModifyUserID {
		if member, ok := mapUserId[getKey(item.UserId)]; ok {
			member.Role = item.Role
		}
	}

	/*
		for _, member := range group.DecryptedGroup.Members {
			key := getKey(member.UserId)
			if _, ok := mapModifyUserID[key]; ok {
				member.Role = mapModifyUserID[key].Role
			}
		}
	*/

	return nil

}

func (g *GroupChangeApplicator) ApplyDeleteMembers(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	deleteMembers []*signalservice.GroupChange_Actions_DeleteMemberAction, groupImmut *GroupV2) error {

	if len(deleteMembers) == 0 {
		return nil
	}

	if !isDeleteMemberAllowed(user, groupImmut, deleteMembers) {
		return errors.New("Forbidden delete")
	}

	mapDeleteUserId := make(map[string]struct{})
	for _, action := range deleteMembers {
		key := getKey(action.DeletedUserId)
		if _, ok := mapDeleteUserId[key]; ok {
			return errors.New("BadRequset Duplicates userId")
		}
		mapDeleteUserId[key] = struct{}{}
	}
	mapUserUsrId := make(map[string]struct{})
	for _, member := range group.DecryptedGroup.Members {
		mapUserUsrId[getKey(member.Uuid)] = struct{}{}
	}
	for k := range mapDeleteUserId {
		if _, ok := mapUserUsrId[k]; !ok {
			return errors.New("BadReqset memberlist lost delete userId")
		}
	}
	var memberShip []*signalservice.DecryptedMember
	for _, member := range group.DecryptedGroup.Members {
		if _, ok := mapDeleteUserId[getKey(member.Uuid)]; !ok {
			memberShip = append(memberShip, member)
		}
	}
	group.DecryptedGroup.Members = memberShip

	return nil

}

func (g *GroupChangeApplicator) ApplyAddMembers(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	addMembers []*signalservice.GroupChange_Actions_AddMemberAction, groupImmut *GroupV2) error {

	if len(addMembers) == 0 {
		return nil
	}
	if !isAddMemberAllowed(user, inviteLinkPassword, groupImmut, addMembers) {
		return entities.Status(http.StatusForbidden, ("addMember forbidden"))
	}

	mapModifyUserId := make(map[string]struct{})
	for _, action := range addMembers {
		key := getKey(action.Added.UserId)
		if _, ok := mapModifyUserId[key]; ok {
			return entities.Status(http.StatusBadRequest, "BadRequset Duplicates userId")
		}
		mapModifyUserId[key] = struct{}{}
	}

	mapUserId := make(map[string]struct{})
	for _, item := range groupImmut.DecryptedGroup.Members {
		mapUserId[getKey(item.Uuid)] = struct{}{}
	}

	for k := range mapModifyUserId {
		if _, ok := mapUserId[k]; ok {
			return entities.Status(http.StatusBadRequest, " add merber userId is exsit member ship")
		}

	}

	b := isAdminstrator(user, groupImmut)
	for _, action := range addMembers {

		if action.Added.Role == signalservice.Member_ADMINISTRATOR && !b {
			return entities.Status(http.StatusForbidden, ("yy Forbidden"))
		}

		userId := action.Added.UserId
		if len(userId) == 0 {
			return entities.Status(http.StatusBadRequest, "addMember useId is empty")
		}
		if len(action.Added.ProfileKey) == 0 {
			return entities.Status(http.StatusBadRequest, "addMember ProfileKey is empty ")
		}
		if action.Added.Role == signalservice.Member_UNKNOWN {
			return entities.Status(http.StatusBadRequest, "addMember role is unknown")
		}
		member := &signalservice.DecryptedMember{
			Role:             action.Added.Role,
			JoinedAtRevision: group.Revision + 1,
			Uuid:             userId,
			ProfileKey:       action.Added.ProfileKey,
		}

		group.DecryptedGroup.Members = append(group.DecryptedGroup.Members, member)

		var pendingProfileKeyShip []*signalservice.DecryptedPendingMember

		for _, value := range group.DecryptedGroup.PendingMembers {
			if _, ok := mapModifyUserId[getKey(value.Uuid)]; !ok {
				pendingProfileKeyShip = append(pendingProfileKeyShip, value)
			}
		}
		group.DecryptedGroup.PendingMembers = pendingProfileKeyShip

		var pendingAdminApprovalShip []*signalservice.DecryptedRequestingMember

		for _, value := range group.DecryptedGroup.RequestingMembers {
			if _, ok := mapModifyUserId[getKey(value.Uuid)]; !ok {
				pendingAdminApprovalShip = append(pendingAdminApprovalShip, value)
			}
		}
		group.DecryptedGroup.RequestingMembers = pendingAdminApprovalShip

	}

	return nil
}
