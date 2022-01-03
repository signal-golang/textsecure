package groupsv2

import (
	zkgroup "github.com/nanu-c/zkgroup"
	"github.com/signal-golang/textsecure/config"
	"github.com/signal-golang/textsecure/helpers"
	log "github.com/sirupsen/logrus"
)

// todo handle group join requests via link
func (g *GroupV2) CheckJoinStatus() error {
	log.Debugln("[textsecure][groupsv2] check join status")
	found := false
	if g.DecryptedGroup != nil {
		for _, m := range g.DecryptedGroup.Members {
			if helpers.HexToUUID(idToHex(m.Uuid)) == config.ConfigFile.UUID {
				found = true
			}
		}
	} else {
		for _, m := range g.GroupContext.Members {
			uuid, err := g.decryptUUID(m.UserId)
			if err != nil {
				return err
			}
			if helpers.HexToUUID(idToHex(uuid)) == config.ConfigFile.UUID {
				found = true
			}
		}
	}
	if found {
		g.JoinStatus = GroupV2JoinsStatusMember
	} else {
		g.JoinStatus = GroupV2JoinsStatusInvite
	}
	log.Debugln("[textsecure][groupsv2] check join status is", g.JoinStatus)

	return nil
}

func (g *GroupV2) checkCipher() error {
	if g.cipher == nil {
		groupSecretParams, err := zkgroup.NewGroupSecretParams(g.MasterKey)
		if err != nil {
			return err
		}
		g.cipher = zkgroup.NewClientZkGroupCipher(groupSecretParams)
	}
	return nil
}
