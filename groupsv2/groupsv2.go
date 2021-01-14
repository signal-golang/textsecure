package groupsv2

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	zkgroup "github.com/nanu-c/zkgroup"
	signalservice "github.com/signal-golang/textsecure/protobuf"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v2"
)

const ZKGROUP_SERVER_PUBLIC_PARAMS = "AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X0="
const HIGHEST_KNOWN_EPOCH = 1

var (
	groupURLHost   = "group.signal.org"
	groupURLPrefix = "https://" + groupURLHost + "/#"
)

// GroupV2 holds group metadata.
type GroupV2 struct {
	MasterKey      []byte
	Hexid          string
	Name           string
	Revision       uint32
	DecryptedGroup *signalservice.DecryptedGroup
}

var (
	groupV2Dir string
	groupsV2   = map[string]*GroupV2{}
)

// idToHex returns the hex representation of the group id byte-slice
// to be used as both keys in the map and for naming the files.
func idToHex(id []byte) string {
	return hex.EncodeToString(id)
}

func GroupInviteLinkUrl() {

}

func GroupLinkPassword() {

}

func handleGroupLinkUrl() {

}
func createAcceptInviteChange() {

}

// GroupV2Message defines a group v2 message type
type GroupV2MessageContext struct {
	MasterKey   []byte // Masterkey is the unique identifier
	Revision    uint32 // holds the current revision number, if mismatch fetch the steps in between
	GroupChange []byte // protobuf of signalservice.GroupChange
}

func SetupGroups(path string) error {
	groupV2Dir = filepath.Join(path, "groupsv2")
	if err := os.MkdirAll(groupV2Dir, 0700); err != nil {
		return err
	}
	return nil
}
func HandleGroupsV2(src string, dm *signalservice.DataMessage) (*GroupV2, error) {
	groupContext := dm.GetGroupV2()
	if groupContext == nil {
		return nil, nil
	}
	groupChange := &signalservice.GroupChange{}
	err := proto.Unmarshal(groupContext.GroupChange, groupChange)
	if err != nil {
		log.Errorln(err)
	}
	// verify server signature
	zkGroupServerPublicParams, _ := base64.StdEncoding.DecodeString(ZKGROUP_SERVER_PUBLIC_PARAMS)
	serverPublicParams, err := zkgroup.NewServerPublicParams(zkGroupServerPublicParams)
	if err != nil {
		log.Errorln("[textsecure] [groupsv2] server public params", err)
	} else {
		err = serverPublicParams.VerifySignature(groupChange.GetActions(), groupChange.GetServerSignature())
		if err != nil {
			log.Errorln("[textsecure] [groupsv2] signature verification failed", err)
			return nil, err
		}
		log.Debugln("[textsecure] [groupsv2] signature verification succesful")

	}

	hexid := idToHex(groupContext.GetMasterKey())
	// find group
	group, err := loadGroupV2(hexid)
	log.Debugln("[textsecure][groupsv2] handle group action ", hexid)
	if err != nil {
		log.Errorln("[textsecure][groupsv2]1 handle groupv2", err)
		group = &GroupV2{
			MasterKey:      groupContext.GetMasterKey(),
			Hexid:          hexid,
			Revision:       groupContext.GetRevision(),
			DecryptedGroup: &signalservice.DecryptedGroup{},
		}
		groupsV2[hexid] = group
		saveGroupV2(hexid)

	}
	err = saveGroupV2(hexid)
	if err != nil {
		log.Debugln("[textsecure][groupsv2]2  handle groupv2 save", err)
	}
	groupSecrets, err := zkgroup.NewGroupSecretParams(group.MasterKey)
	if err != nil {
		log.Debugln("[textsecure][groupsv2] 3handle groupv2", err)
	}
	clientZipher := zkgroup.NewClientZkGroupCipher(groupSecrets)
	// get group changes

	// get group actions, maybe needs to be decrypted
	groupActions := &signalservice.GroupChange_Actions{}
	err = proto.Unmarshal(groupChange.Actions, groupActions)
	if err != nil {
		log.Errorln(err)
	}
	decryptedGroupChange := decryptGroupChangeActions(groupActions, clientZipher)
	handleGroupChangesForGroup(decryptedGroupChange, hexid)
	group.DecryptedGroup.PendingMembers = decryptedGroupChange.NewPendingMembers

	fmt.Printf("decryptedGroupChange %+v\n", decryptedGroupChange)
	return group, nil
}
func handleGroupChangesForGroup(groupChange *signalservice.DecryptedGroupChange, hexid string) {
	// if groupChange.NewPendingMembers != nil {
	// 	for _, m := range groupChange.NewPendingMembers {
	// 		createRequestForGroup(hexid, m.Uuid)
	// 	}
	// }

}
func decryptPendingMembers(pendingMembers []*signalservice.GroupChange_Actions_AddPendingMemberAction,
	clientCipher *zkgroup.ClientZkGroupCipher) []*signalservice.DecryptedPendingMember {
	var decryptedPendingMembers []*signalservice.DecryptedPendingMember
	for _, pendingMember := range pendingMembers {
		added := pendingMember.GetAdded()
		member := added.GetMember()
		uuidCipherText := member.GetUserId()
		uuid, err := clientCipher.DecryptUUID(uuidCipherText)
		if err != nil {
			log.Errorln(err)
		}
		addedByUuid, err := clientCipher.DecryptUUID(added.GetAddedByUserId())
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
func decryptDeletePendingMembers(deletedPendingMembers []*signalservice.GroupChange_Actions_DeletePendingMemberAction,
	clientCipher *zkgroup.ClientZkGroupCipher) []*signalservice.DecryptedPendingMember {
	for _, deletedPendingMember := range deletedPendingMembers {

		uuid, err := clientCipher.DecryptUUID(deletedPendingMember.DeletedUserId)
		if err != nil {
			log.Errorln(err)
		}
		log.Debugln("[textsecure][groupsv2] deletePendingMember", idToHex(uuid))

	}
	return nil
}
func decryptGroupChangeActions(groupActions *signalservice.GroupChange_Actions,
	clientCipher *zkgroup.ClientZkGroupCipher) *signalservice.DecryptedGroupChange {
	decryptedGroupChange := &signalservice.DecryptedGroupChange{}
	if groupActions.SourceUuid != nil {
		uuid, err := clientCipher.DecryptUUID(groupActions.SourceUuid)
		log.Debugln("[textsecure][groupsv2] SourceUuid", idToHex(uuid), err)
	}
	log.Debugln("[textsecure][groupsv2] Revision", groupActions.Revision)
	if groupActions.AddMembers != nil {
		log.Debugln("[textsecure][groupsv2] AddMembers")
	}
	if groupActions.DeleteMembers != nil {
		log.Debugln("[textsecure][groupsv2] DeleteMembers")
		decryptDeletePendingMembers(groupActions.DeletePendingMembers, clientCipher)
	}
	if groupActions.ModifyMemberRoles != nil {
		log.Debugln("[textsecure][groupsv2] ModifyMemberRoles")
	}
	if groupActions.ModifyMemberProfileKeys != nil {
		log.Debugln("[textsecure][groupsv2] ModifyMemberProfileKeys")
	}
	if groupActions.AddPendingMembers != nil {
		log.Debugln("[textsecure][groupsv2] AddPendingMembers")
		decryptedGroupChange.NewPendingMembers = decryptPendingMembers(groupActions.AddPendingMembers, clientCipher)
	}
	if groupActions.DeletePendingMembers != nil {
		log.Debugln("[textsecure][groupsv2] DeletePendingMembers")
	}
	if groupActions.PromotePendingMembers != nil {
		log.Debugln("[textsecure][groupsv2] PromotePendingMembers")
	}
	if groupActions.ModifyTitle != nil {
		log.Debugln("[textsecure][groupsv2] ModifyTitle")
	}
	if groupActions.ModifyAvatar != nil {
		log.Debugln("[textsecure][groupsv2] ModifyAvatar")
	}
	if groupActions.ModifyDisappearingMessagesTimer != nil {
		log.Debugln("[textsecure][groupsv2] ModifyDisappearingMessagesTimer")
	}
	if groupActions.ModifyAttributesAccess != nil {
		log.Debugln("[textsecure][groupsv2] ModifyAttributesAccess")
	}
	if groupActions.ModifyMemberAccess != nil {
		log.Debugln("[textsecure][groupsv2] ModifyMemberAccess")
	}
	if groupActions.ModifyAddFromInviteLinkAccess != nil {
		log.Debugln("[textsecure][groupsv2] ModifyAddFromInviteLinkAccess")
	}
	if groupActions.AddRequestingMembers != nil {
		log.Debugln("[textsecure][groupsv2] AddRequestingMembers")
	}
	if groupActions.DeleteRequestingMembers != nil {
		log.Debugln("[textsecure][groupsv2] DeleteRequestingMembers")
	}
	if groupActions.PromoteRequestingMembers != nil {
		log.Debugln("[textsecure][groupsv2] PromoteRequestingMembers")
	}
	if groupActions.ModifyInviteLinkPassword != nil {
		log.Debugln("[textsecure][groupsv2] ModifyInviteLinkPassword")
	}
	return decryptedGroupChange
}

func decryptUuidOrUnknown(uuidCipherTex []byte) *[]byte {
	// https://github.com/signalapp/zkgroup/blob/ea80ccc47bc8363d15906fb0f57588e940b589a0/rust/src/api/groups/group_params.rs#L118-L124
	return nil
}

// saveGroup stores a group's state in a file.
func saveGroupV2(hexid string) error {
	b, err := yaml.Marshal(groupsV2[hexid])
	if err != nil {
		return err
	}
	log.Debugln("[textsecure] save groupv2", idToPath(hexid))
	return ioutil.WriteFile(idToPath(hexid), b, 0600)
}

// loadGroup loads a group's state from a file.
func loadGroupV2(hexid string) (*GroupV2, error) {
	b, err := ioutil.ReadFile(idToPath(hexid))
	if err != nil {
		return nil, err
	}

	group := &GroupV2{}
	err = yaml.Unmarshal(b, group)
	if err != nil {
		return nil, err
	}
	groupsV2[hexid] = group
	return group, nil
}

// idToPath returns the path of the file for storing a group's state
func idToPath(hexid string) string {
	return filepath.Join(groupV2Dir, hexid)
}
