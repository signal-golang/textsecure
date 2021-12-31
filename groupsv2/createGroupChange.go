package groupsv2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	zkgroup "github.com/nanu-c/zkgroup"
	"github.com/signal-golang/textsecure/config"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	log "github.com/sirupsen/logrus"
)

const (
	randomLength = 32
)

func randBytes(data []byte) {
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
}
func createGroupContextForGroup(hexid string) *signalservice.GroupContextV2 {
	var revision uint32
	revision = groupsV2[hexid].GroupContext.Revision + 1
	return &signalservice.GroupContextV2{
		MasterKey: groupsV2[hexid].MasterKey,
		Revision:  &revision,
	}
}

func CreatePromotePendingMemberAction(uuid []byte, group string) []byte {
	// return &signalservice.GroupChange_Actions{}

	return []byte{}

}
func CreateGroupChangeFromGroupActions(actions []byte) []byte {
	groupChange := signalservice.GroupChange{
		Actions:         actions,
		ServerSignature: nil,
		ChangeEpoch:     HIGHEST_KNOWN_EPOCH,
	}
	log.Debugln(groupChange)
	return []byte{}

}

// func CreatePromotePendingMemberActionMessage(uuid []byte, group string) *signalservice.GroupContextV2 {
// 	groupActions := CreatePromotePendingMemberAction(uuid, group)

// 	return nil

// }

func creatEmptyGroupChangeActions() *signalservice.GroupChange_Actions {
	return &signalservice.GroupChange_Actions{}
}

func (g *GroupV2) AddPendingMembers(uuid []byte) (*signalservice.GroupChange_Actions, error) {
	log.Debugln("[textsecure] groupsv2 AddPendingMembers (only works for self )")
	member, err := g.findMemberByUuid(config.ConfigFile.UUID)

	if err != nil {
		log.Debugln("[textsecure] member not found")
		return nil, err
	}
	member.ProfileKey = config.ConfigFile.ProfileKey
	// groupSecrets, err := zkgroup.NewGroupSecretParams(g.MasterKey)
	if err != nil {
		log.Debugln("[textsecure] CreateRequestForGroup 1", err)
		return nil, err
	}

	zkGroupServerPublicParams, err := base64.StdEncoding.DecodeString(config.ZKGROUP_SERVER_PUBLIC_PARAMS)
	if err != nil {
		log.Debugln("[textsecure] CreateRequestForGroup 2", err)
		return nil, err
	}
	serverPublicParams, err := zkgroup.NewServerPublicParams(zkGroupServerPublicParams)
	if err != nil {
		log.Debugln("[textsecure] CreateRequestForGroup 8", err)
		return nil, err
	}

	groupSecretParams, err := zkgroup.NewGroupSecretParams(g.MasterKey)
	if err != nil {
		log.Debugln("[textsecure] CreateRequestForGroup 9", err)
		return nil, err
	}
	log.Debugln("[textsecure] CreateRequestForGroup 9.1", len(config.ConfigFile.ProfileKeyCredential))
	presentation, err := serverPublicParams.CreateProfileKeyCredentialPresentation(groupSecretParams, config.ConfigFile.ProfileKeyCredential)
	if err != nil {
		log.Debugln("[textsecure] CreateRequestForGroup 10", err)
		return nil, err
	}
	member.Presentation = presentation
	member.JoinedAtRevision = g.GroupContext.Revision + 1
	member.Role = 1

	groupChangeActions := &signalservice.GroupChange_Actions{}
	groupChangeActions.AddMembers = append(groupChangeActions.AddMembers,
		&signalservice.GroupChange_Actions_AddMemberAction{
			Added: member,
		})
	groupChangeActions.SourceUuid = uuid
	groupChangeActions.Revision = g.DecryptedGroup.Revision + 1
	fmt.Printf("[textsecure] AddPendingMembers %+v\n", groupChangeActions)

	auth, err := NewGroupsV2Authorization(uuidToByte(config.ConfigFile.UUID), groupSecretParams)
	err = PatchGroupV2(groupChangeActions, auth)
	if err != nil {
		log.Debugln("[textsecure] CreateRequestForGroup2", uuid, err)
		return nil, err
	}
	return groupChangeActions, nil
}

func (g *GroupV2) findMemberByUuid(uuid string) (*signalservice.Member, error) {
	log.Debugln(len(g.GroupContext.PendingMembers))
	for _, member := range g.GroupContext.PendingMembers {
		d, err := g.decryptUUID(member.Member.UserId)
		if err != nil {
			log.Debugln(err)
		} else {
			mUUID := HexToUUID(idToHex(d))
			log.Debugln(uuid, mUUID)
			if mUUID == uuid {
				return &signalservice.Member{
					UserId:       member.Member.UserId,
					ProfileKey:   member.Member.ProfileKey,
					Presentation: member.Member.Presentation,
				}, nil
			}
		}

	}
	return nil, fmt.Errorf("member not found")
}

func HexToUUID(id string) string {
	if len(id) != 32 {
		return id
	}
	msbHex := id[:16]
	lsbHex := id[16:]
	return msbHex[:8] + "-" + msbHex[8:12] + "-" + msbHex[12:] + "-" + lsbHex[:4] + "-" + lsbHex[4:]
}
