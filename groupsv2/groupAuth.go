package groupsv2

import (
	"bytes"

	"github.com/signal-golang/textsecure/entities"
	signalservice "github.com/signal-golang/textsecure/protobuf"
)

func isPromoteMembersPendingAdminApprovalAllowed(user *entities.GroupUser, group *GroupV2) bool {
	return isAdminstrator(user, group)

}

func isDeleteMembersPendingAdminApprovalAllowed(user *entities.GroupUser, group *GroupV2, actions []*signalservice.GroupChange_Actions_DeleteRequestingMemberAction) bool {
	return isAdminstrator(user, group) ||
		len(actions) == 1 && user.IsMember(actions[0].DeletedUserId, group.MasterKey)

}

func isAddMembersPendingAdminApprovalAllowed(user *entities.GroupUser, inviteLinkPassword []byte, group *GroupV2) bool {
	return group.DecryptedGroup.AccessControl.AddFromInviteLink == signalservice.AccessControl_ADMINISTRATOR &&
		bytes.Equal(group.DecryptedGroup.InviteLinkPassword, inviteLinkPassword)
}

func isModifyAnnouncementsOnlyAllowed(user *entities.GroupUser, group *GroupV2) bool {
	return isAdminstrator(user, group)

}

func isModifyInviteLinkPasswordAllowed(user *entities.GroupUser, group *GroupV2) bool {
	return isAdminstrator(user, group)

}

func isModifyAddFromInviteLinkAccessControlAllowe(user *entities.GroupUser, group *GroupV2) bool {
	return isAdminstrator(user, group)

}
func isModifyAttributesAllowed(user *entities.GroupUser, group *GroupV2) bool {
	source := GetSourceMember(user, group)
	if source == nil {
		return false
	}
	switch group.DecryptedGroup.AccessControl.Attributes {
	case signalservice.AccessControl_ANY:
		return true
	case signalservice.AccessControl_MEMBER:
		return true
	case signalservice.AccessControl_ADMINISTRATOR:
		return source.Role == signalservice.Member_ADMINISTRATOR
	default:
		return false
	}
}
func isDeleteMembersPendingProfileKeyAllowed(user *entities.GroupUser, group *GroupV2,
	actions []*signalservice.GroupChange_Actions_DeletePendingMemberAction) bool {
	if isAdminstrator(user, group) {
		return true
	}
	return len(actions) == 1 && user.IsMember(actions[0].DeletedUserId, group.MasterKey)
}
func isAddMembersPendingProfileKeyAllowed(user *entities.GroupUser, group *GroupV2) bool {

	member := GetSourceMember(user, group)
	if member == nil {
		return false
	}

	return member.Role == signalservice.Member_ADMINISTRATOR ||
		group.DecryptedGroup.AccessControl.Members == signalservice.AccessControl_MEMBER ||
		group.DecryptedGroup.AccessControl.Members == signalservice.AccessControl_ANY

}

func isAdminstrator(user *entities.GroupUser, group *GroupV2) bool {
	for _, member := range group.DecryptedGroup.Members {
		if user.IsMember(member.Uuid, group.MasterKey) {
			return member.Role == signalservice.Member_ADMINISTRATOR
		}
	}
	return false
}

func isDeleteMemberAllowed(user *entities.GroupUser,
	group *GroupV2,
	members []*signalservice.GroupChange_Actions_DeleteMemberAction) bool {
	if isAdminstrator(user, group) {
		return true
	}
	return len(members) == 1 && user.IsMember(members[0].DeletedUserId, group.MasterKey)

}
func isAddMemberAllowed(user *entities.GroupUser,
	inviteLinkPassword []byte,
	group *GroupV2,
	actions []*signalservice.GroupChange_Actions_AddMemberAction) bool {
	member := GetSourceMember(user, group)
	if member != nil {
		switch member.Role {
		case signalservice.Member_ADMINISTRATOR:
			return true
		case signalservice.Member_DEFAULT:
			return group.DecryptedGroup.AccessControl.Members == signalservice.AccessControl_MEMBER ||
				group.DecryptedGroup.AccessControl.Members == signalservice.AccessControl_ANY
		default:
			return false

		}
	}

	return (group.DecryptedGroup.AccessControl.Members == signalservice.AccessControl_ANY ||
		(group.DecryptedGroup.AccessControl.AddFromInviteLink == signalservice.AccessControl_ANY &&
			bytes.Equal(group.DecryptedGroup.InviteLinkPassword, inviteLinkPassword))) &&
		len(actions) == 1 &&
		user.IsMember(actions[0].Added.UserId, group.MasterKey)

}
func IsAccessRequiredOneOf(valueToTest signalservice.AccessControl_AccessRequired, acceptableValues ...signalservice.AccessControl_AccessRequired) bool {
	for _, item := range acceptableValues {
		if valueToTest == item {
			return true
		}
	}
	return false
}

func IsMember(user *entities.GroupUser, group *GroupV2) bool {
	for _, item := range group.DecryptedGroup.Members {
		if user.IsMember(item.Uuid, group.MasterKey) {
			return true
		}
	}
	return false
}

func IsMemberPendingProfileKey(user *entities.GroupUser, group *GroupV2) bool {
	for _, item := range group.DecryptedGroup.PendingMembers {
		if user.IsMember(item.Uuid, group.MasterKey) {
			return true
		}
	}
	return false
}

func IsMemberPendingAdminApproval(user *entities.GroupUser, group *GroupV2) bool {
	for _, item := range group.DecryptedGroup.RequestingMembers {
		if user.IsMember(item.Uuid, group.MasterKey) {
			return true
		}
	}
	return false
}

func GetSourceMember(user *entities.GroupUser, group *GroupV2) *signalservice.DecryptedMember {
	for _, member := range group.DecryptedGroup.Members {
		if user.IsMember(member.GetUuid(), group.MasterKey) {
			return member
		}
	}
	return nil
}

//
func GetMemberPendingProfileKey(user *entities.GroupUser, group *GroupV2) *signalservice.DecryptedPendingMember {

	for _, item := range group.DecryptedGroup.PendingMembers {
		if user.IsMember(item.Uuid, group.MasterKey) {
			return item
		}
	}
	return nil

}

func GetMemberPendingAdminApproval(user *entities.GroupUser, group *GroupV2) *signalservice.DecryptedRequestingMember {

	for _, item := range group.DecryptedGroup.RequestingMembers {
		if user.IsMember(item.Uuid, group.MasterKey) {
			return item
		}
	}
	return nil

}
