package groupsv2

import (
	"fmt"

	zkgroup "github.com/nanu-c/zkgroup"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	log "github.com/sirupsen/logrus"
)

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

func CreateRequestForGroup(gID string, uuid []byte) *signalservice.GroupChange_Actions {
	group := groupsV2[gID]
	groupSecrets, err := zkgroup.NewGroupSecretParams(group.MasterKey)
	if err != nil {
		log.Debugln("[textsecure] CreateRequestForGroup 1", err)
	}
	clientZipher := zkgroup.NewClientZkGroupCipher(groupSecrets)
	presentation, err := clientZipher.EncryptUUID(uuid)
	if err != nil {
		log.Debugln("[textsecure] CreateRequestForGroup2", uuid, err)
	}
	groupChangeActions := &signalservice.GroupChange_Actions{}
	groupChangeActions.PromotePendingMembers = append(groupChangeActions.PromotePendingMembers,
		&signalservice.GroupChange_Actions_PromotePendingMemberAction{
			Presentation: presentation,
		})
	fmt.Printf("%+v\n", groupChangeActions)
	return groupChangeActions
}
