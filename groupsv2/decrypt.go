package groupsv2

import (
	"strings"

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

	decryptedGroup.Title = strings.Replace(strings.Replace(strings.Replace(strings.Replace(strings.TrimSpace(string(title)), "\x02", "", -1), "\x03", "", -1), "\x04", "", -1), "\x05", "", -1)
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
