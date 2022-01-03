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
	"google.golang.org/protobuf/proto"
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

func creatEmptyGroupChangeActions() *signalservice.GroupChange_Actions {
	return &signalservice.GroupChange_Actions{}
}

func (g *GroupV2) AddPendingMembers(uuid []byte) error {
	log.Debugln("[textsecure][groupsv2] AddPendingMembers (only works for self )")
	member, err := g.findMemberByUuid(config.ConfigFile.UUID)
	if err != nil {
		log.Debugln("[textsecure] member not found")
		return err
	}
	member.ProfileKey = config.ConfigFile.ProfileKey
	if err != nil {
		return err
	}

	zkGroupServerPublicParams, err := base64.StdEncoding.DecodeString(config.ZKGROUP_SERVER_PUBLIC_PARAMS)
	if err != nil {
		return err
	}
	serverPublicParams, err := zkgroup.NewServerPublicParams(zkGroupServerPublicParams)
	if err != nil {
		return err
	}

	groupSecretParams, err := zkgroup.NewGroupSecretParams(g.MasterKey)
	if err != nil {
		return err
	}
	presentation, err := serverPublicParams.CreateProfileKeyCredentialPresentation(groupSecretParams, config.ConfigFile.ProfileKeyCredential)
	if err != nil {
		return err
	}
	groupChangeActions := &signalservice.GroupChange_Actions{}
	groupChangeActions.PromotePendingMembers = append(groupChangeActions.PromotePendingMembers,
		&signalservice.GroupChange_Actions_PromotePendingMemberAction{
			Presentation: presentation,
		})
	groupChangeActions.SourceUuid = uuid
	groupChangeActions.Revision = g.DecryptedGroup.Revision + 1

	auth, err := NewGroupsV2Authorization(uuid, groupSecretParams)
	if err != nil {
		return err
	}
	out, err := proto.Marshal(groupChangeActions)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	err = PatchGroupV2(out, auth)
	if err != nil {
	}
	g.JoinStatus = GroupV2JoinsStatusMember
	g.UpdateGroupFromServer()
	return nil
}
func (g *GroupV2) EncryptUUID(uuid []byte) ([]byte, error) {
	if g.cipher == nil {
		groupSecretParams, err := zkgroup.NewGroupSecretParams(g.MasterKey)
		if err != nil {
			return nil, err
		}
		g.cipher = zkgroup.NewClientZkGroupCipher(groupSecretParams)
	}
	return g.cipher.EncryptUUID(uuid)
}
func (g *GroupV2) findMemberByUuid(uuid string) (*signalservice.Member, error) {
	for _, member := range g.GroupContext.PendingMembers {
		d, err := g.decryptUUID(member.Member.UserId)
		if err != nil {
			return nil, err
		} else {
			mUUID := HexToUUID(idToHex(d))
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
