package groupsv2

import (
	"strings"
	"unicode"

	"github.com/nanu-c/zkgroup"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	log "github.com/sirupsen/logrus"
)

func (g *GroupV2) decryptGroupFromServer(group *signalservice.Group) error {
	newGroup := &GroupV2{
		MasterKey:    g.MasterKey,
		GroupContext: *group,
	}
	decryptedGroup, err := newGroup.decryptGroup()
	g.GroupContext = newGroup.GroupContext
	g.DecryptedGroup = decryptedGroup
	g.checkJoinStatus()
	return err
}
func (g *GroupV2) decryptGroup() (*signalservice.DecryptedGroup, error) {
	log.Debugln("[textsecure][groupsv2] decrypt group")
	if g.cipher == nil {
		groupSecretParams, err := zkgroup.NewGroupSecretParams(g.MasterKey)
		if err != nil {
			return nil, err
		}
		g.cipher = zkgroup.NewClientZkGroupCipher(groupSecretParams)
	}
	membersList := g.GroupContext.GetMembers()

	// pendingMembersList := group.GetPendingMembers()
	// requestingMembersList := group.GetRequestingMembers()
	// len(membersList)
	decryptedMembers := []*signalservice.DecryptedMember{}
	// decryptedPendingMembers = []*signalservice.DecryptedPendingMember{}
	// decryptedRequestingMembers = []*signalservice.DecryptedRequestingMember{}

	for _, member := range membersList {
		decryptedMember, err := g.decryptMember(member)
		if err == nil {
			decryptedMembers = append(decryptedMembers, decryptedMember)
		}
	}
	// TODO: decrypt pending and requesting members
	decryptedGroup := &signalservice.DecryptedGroup{}
	title, err := g.cipher.DecryptBlob(g.GroupContext.GetTitle())
	if err != nil {
		return nil, err
	}
	cleanTitle := strings.Map(func(r rune) rune {
		if unicode.IsGraphic(r) {
			return r
		}
		return -1
	}, string(title))
	decryptedGroup.Title = cleanTitle
	decryptedGroup.Revision = g.GroupContext.Revision
	decryptedGroup.Avatar = g.GroupContext.GetAvatar()
	decryptedGroup.AccessControl = g.GroupContext.GetAccessControl()
	decryptedGroup.Members = decryptedMembers
	return decryptedGroup, nil
}

func (g *GroupV2) decryptMember(member *signalservice.Member) (*signalservice.DecryptedMember, error) {
	var err error
	decryptedMember := &signalservice.DecryptedMember{}

	decryptedMember.JoinedAtRevision = member.GetJoinedAtRevision()
	decryptedMember.Role = member.GetRole()
	if member.GetPresentation() == nil {
		// TODO: check valid Uuid
		decryptedMember.Uuid, err = g.decryptUUID(member.GetUserId())
		if err != nil {
			return nil, err
		}
		decryptedMember.ProfileKey, err = g.cipher.DecryptProfileKey(member.GetProfileKey(), decryptedMember.Uuid)

	} else {
		//TODO: check valid presentation
		profileKeyCredentialPresentation, err := zkgroup.NewAuthCredentialPresentation(member.GetPresentation())
		if err != nil {
			return nil, err
		}
		uuidCiphertext, err := profileKeyCredentialPresentation.UUIDCiphertext()
		if err != nil {
			return nil, err
		}
		decryptedMember.Uuid, err = g.decryptUUID(uuidCiphertext)
		if err != nil {
			return nil, err
		}
		profileKeyCiphertext, err := profileKeyCredentialPresentation.ProfileKeyCiphertext()
		if err != nil {
			return nil, err
		}
		decryptedMember.ProfileKey, err = g.cipher.DecryptProfileKey(profileKeyCiphertext, decryptedMember.Uuid)
		if err != nil {
			return nil, err
		}

	}

	return decryptedMember, nil

}

func (g *GroupV2) decryptUUID(uuid []byte) ([]byte, error) {
	return g.cipher.DecryptUUID(uuid)
}

func (g *GroupV2) decryptPendingMembers(pendingMembers []*signalservice.GroupChange_Actions_AddPendingMemberAction) []*signalservice.DecryptedPendingMember {
	var decryptedPendingMembers []*signalservice.DecryptedPendingMember
	for _, pendingMember := range pendingMembers {
		added := pendingMember.GetAdded()
		member := added.GetMember()
		uuidCipherText := member.GetUserId()
		uuid, err := g.cipher.DecryptUUID(uuidCipherText)
		if err != nil {
			log.Errorln(err)
		}
		addedByUuid, err := g.cipher.DecryptUUID(added.GetAddedByUserId())
		if err != nil {
			log.Errorln(err)
		}
		log.Debugln("[textsecure][groupsv2] pendingMember", idToHex(uuid))
		decryptedPendingMembers = append(decryptedPendingMembers,
			&signalservice.DecryptedPendingMember{
				Uuid:           uuid,
				Role:           member.GetRole(),
				AddedByUuid:    addedByUuid,
				UuidCipherText: uuidCipherText,
				Timestamp:      added.GetTimestamp(),
			},
		)
	}
	return decryptedPendingMembers
}
func (g *GroupV2) decryptDeletePendingMembers(deletedPendingMembers []*signalservice.GroupChange_Actions_DeletePendingMemberAction,
) []*signalservice.DecryptedPendingMember {
	for _, deletedPendingMember := range deletedPendingMembers {

		uuid, err := g.cipher.DecryptUUID(deletedPendingMember.DeletedUserId)
		if err != nil {
			log.Errorln(err)
		}
		log.Debugln("[textsecure][groupsv2] deletePendingMember", idToHex(uuid))

	}
	return nil
}
