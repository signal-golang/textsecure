package groupsv2

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"

	zkgroup "github.com/nanu-c/zkgroup"
	uuidUtil "github.com/satori/go.uuid"
	"github.com/signal-golang/textsecure/config"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	"github.com/signal-golang/textsecure/transport"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v2"
)

const (
	HIGHEST_KNOWN_EPOCH = 1
	GROUPSV2_GROUP      = "/v1/groups/"
	GROUPSV2_GROUP_JOIN = "/v1/groups/join/%s"
)

const (
	GroupV2JoinsStatusMember  = 0
	GroupV2JoinsStatusInvite  = 1
	GroupV2JoinsStatusRequest = 2
	GroupV2JoinsStatusRemoved = 3
)

var (
	groupURLHost   = "signal.group"
	groupURLPrefix = "https://" + groupURLHost + "/#"
	groupV2Dir     string
	groupsV2       = map[string]*GroupV2{}
)

// GroupV2 holds group metadata.
type GroupV2 struct {
	MasterKey         []byte
	Hexid             string
	GroupContext      signalservice.Group
	cipher            *zkgroup.ClientZkGroupCipher
	DecryptedGroup    *signalservice.DecryptedGroup
	GroupAction       *signalservice.DecryptedGroupChange
	JoinStatus        int
	Revision          uint32
	AnnouncementsOnly bool
}

// idToHex returns the hex representation of the group id byte-slice
// to be used as both keys in the map and for naming the files.
func idToHex(id []byte) string {
	return hex.EncodeToString(id)
}

// Parse an arbitrary string to a Signal group URL.
// If the URL is invalid, nil is returned.
func getGroupUrl(uriString string) *url.URL {
	url, err := url.Parse(uriString)
	if err != nil {
		log.Errorln("[textsecure][groupsv2] GroupInviteLinkUrl error parsing URL", err)
		return nil
	}
	if url.Scheme != "https" {
		log.Errorln("[textsecure][groupsv2] GroupInviteLinkUrl URL invalid scheme ", url.Scheme)
		return nil
	}
	if url.Host != groupURLHost {
		log.Errorln("[textsecure][groupsv2] GroupInviteLinkUrl URL invalid host ", url.Host)
		return nil
	}
	if url.Path != "" {
		log.Errorln("[textsecure][groupsv2] GroupInviteLinkUrl URL path should be empty ", url.Path)
		return nil
	}
	if url.Fragment == "" {
		log.Errorln("[textsecure][groupsv2] GroupInviteLinkUrl URL fragment is empty ")
		return nil
	}
	return url
}

func GroupInviteLinkUrl() {

}

func GroupLinkPassword() {

}

func handleGroupLinkUrl() {

}
func createAcceptInviteChange() {

}
func FindGroup(hexid string) *GroupV2 {
	if len(groupsV2) == 0 {
		group, err := loadGroupV2(hexid)
		if err != nil {
			log.Debugln("[textsecure][groupsv2] FindGroup", err)
			return nil
		}
		return group
	}
	return groupsV2[hexid]
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
func uuidToByte(id string) []byte {
	s, _ := uuidUtil.FromString(id)
	return s.Bytes()
}
func (g *GroupV2) getGroupJoinInfoFromServer(masterKey, groupLinkPassword []byte) (*signalservice.DecryptedGroupJoinInfo, error) {
	groupSecretParams, err := zkgroup.NewGroupSecretParams(masterKey)
	if err != nil {
		return nil, err
	}
	auth, err := NewGroupsV2Authorization(uuidToByte(config.ConfigFile.UUID), groupSecretParams)
	if err != nil {
		return nil, err
	}
	resp, err := transport.StorageTransport.GetWithAuth(fmt.Sprintf(GROUPSV2_GROUP_JOIN, string(groupLinkPassword)), "Basic "+basicAuth(auth.Username, auth.Password))
	if err != nil {
		log.Errorln("[textsecure][groupsv2] getGroupJoinInfoFromServer", err)
		return nil, err
	}
	if resp.IsError() {
		return nil, fmt.Errorf(fmt.Sprintf("getGroupJoinInfoFromServer %s", resp.Status))
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	groupJoinInfo := &signalservice.GroupJoinInfo{}
	err = proto.Unmarshal(buf.Bytes(), groupJoinInfo)
	if err != nil {
		return nil, err
	}
	decryptedGroupJoinInfo, err := g.decryptGroupJoinInfo(groupJoinInfo, groupSecretParams)
	if err != nil {
		return nil, err
	}
	return decryptedGroupJoinInfo, nil
}
func (g *GroupV2) queryGroupChangeFromServer() (*signalservice.Group, error) {
	log.Debugln("[textsecure][groupsv2] queryGroupChangeFromServer")
	groupSecretParams, err := zkgroup.NewGroupSecretParams(g.MasterKey)
	if err != nil {
		return nil, err
	}
	auth, err := NewGroupsV2Authorization(uuidToByte(config.ConfigFile.UUID), groupSecretParams)
	if err != nil {
		return nil, err
	}
	resp, err := transport.StorageTransport.GetWithAuth(GROUPSV2_GROUP, "Basic "+basicAuth(auth.Username, auth.Password))
	if err != nil {
		log.Errorln("[textsecure][groupsv2] queryGroupChangeFromServer", err)
		return nil, err
	}
	if resp.IsError() {
		if resp.Status == 403 {
			return nil, fmt.Errorf(fmt.Sprintf("Not in group %s", resp.Status))
		}
		if resp.Status == 404 {

			return nil, fmt.Errorf(fmt.Sprintf("Group not found %s", resp.Status))
		}
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	group := &signalservice.Group{}
	err = proto.Unmarshal(buf.Bytes(), group)
	g.cipher = zkgroup.NewClientZkGroupCipher(groupSecretParams)

	log.Debugln("[textsecure][groupsv2] queryGroupChangeFromServer group")
	return group, nil

}
func (g *GroupV2) UpdateGroupFromServer() error {
	log.Debugln("[textsecure][groupsv2] update group from server")
	hexid := idToHex(g.MasterKey)
	group := &GroupV2{
		MasterKey: g.MasterKey,
	}
	if groupsV2[hexid] != nil {
		group = groupsV2[hexid]
	}
	// decryptedGroupChange, err := getDecryptedGroupChange(signedGroupChange, groupSecretParams)
	// if err != nil {
	// 	return err
	// }
	groupFromServer, err := group.queryGroupChangeFromServer()
	if err != nil {
		return err
	}
	err = group.decryptGroupFromServer(groupFromServer)
	if err != nil {
		log.Debugln("[textsecure][groupsv2] decryptGroupFromServer", err)
		return err
	}
	groupsV2[hexid] = group
	saveGroupV2(hexid)
	log.Debugln("[textsecure][groupsv2] update group from server")
	g = group

	return nil
}

func HandleGroupsV2(src string, dm *signalservice.DataMessage) (*GroupV2, error) {
	groupContext := dm.GetGroupV2()
	if groupContext == nil {
		return nil, nil
	}
	hexid := idToHex(groupContext.GetMasterKey())
	// search for group
	group, err := loadGroupV2(hexid)
	if err != nil {
		// group not found, create group
		log.Debugln("[textsecure][groupsv2] handle groupv2", err)
		group = &GroupV2{
			MasterKey: groupContext.GetMasterKey(),
			Hexid:     hexid,
			Revision:  groupContext.GetRevision(),
		}
		// TODO: get members from server
		groupsV2[hexid] = group
		err = saveGroupV2(hexid)
		if err != nil {
			log.Error("[textsecure][groupsv2] handle groupv2 save", err)
		}
		err = group.UpdateGroupFromServer()
		if err != nil {
			log.Error("[textsecure][groupsv2] error updating group change from server", err)
		}
		// TODO only update group on wrong revision
	} else if string(group.GroupContext.Title) == "" {
		err = group.UpdateGroupFromServer()
	}
	// handle group changes
	if len(groupContext.GroupChange) > 0 {
		groupChange := &signalservice.GroupChange{}
		err := proto.Unmarshal(groupContext.GroupChange, groupChange)
		if err != nil {
			log.Errorln(err)
		}
		// verify server signature
		zkGroupServerPublicParams, _ := base64.StdEncoding.DecodeString(config.ZKGROUP_SERVER_PUBLIC_PARAMS)
		serverPublicParams, err := zkgroup.NewServerPublicParams(zkGroupServerPublicParams)
		if err != nil {
			log.Errorln("[textsecure][groupsv2] server public params", err)
		} else {
			if len(groupChange.GetActions()) != 0 {
				err = serverPublicParams.VerifySignature(groupChange.GetActions(), groupChange.GetServerSignature())
				if err != nil {
					log.Errorln("[textsecure][groupsv2] signature verification failed", err)
					return nil, err
				}
				log.Debugln("[textsecure][groupsv2] signature verification successful")
			}
		}

		log.Debugln("[textsecure][groupsv2] handle group action ", hexid)

		if err != nil {
			log.Errorln("[textsecure][groupsv2] handle groupv2", err)
		}
		// get group changes

		// get group actions, maybe needs to be decrypted
		groupActions := &signalservice.GroupChange_Actions{}
		err = proto.Unmarshal(groupChange.Actions, groupActions)
		if err != nil {
			log.Errorln(err)
		}
		decryptedGroupChange := group.decryptGroupChangeActions(groupActions)
		handleGroupChangesForGroup(decryptedGroupChange, hexid)
		group.UpdateGroupFromServer()
		if decryptedGroupChange != nil {
			group.GroupAction = decryptedGroupChange
		} else {
			group.GroupAction = nil
		}
	} else if group.DecryptedGroup.Revision != groupContext.GetRevision() {
		log.Debugln("[textsecure][groupsv2] outdated group, update")
		group.UpdateGroupFromServer()
	}
	return group, nil
}

func handleGroupChangesForGroup(groupChange *signalservice.DecryptedGroupChange, hexid string) {
	// if groupChange.NewPendingMembers != nil {
	// 	for _, m := range groupChange.NewPendingMembers {
	// 		createRequestForGroup(hexid, m.Uuid)
	// 	}
	// }

}
func (g *GroupV2) JoinGroup() error {
	err := g.UpdateGroupFromServer()
	if err != nil {
		return err
	}
	uuid, _ := uuidUtil.FromString(config.ConfigFile.UUID)
	err = g.AddPendingMembers(uuid.Bytes())
	if err != nil {
		return err
	}
	log.Infoln("[textsecure][groupv2] joined group ", err)
	return err
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
	log.Debugln("[textsecure][groupv2] save group", idToPath(hexid))
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

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func PatchGroupV2(out []byte,
	groupsV2Authorization *GroupsV2Authorization) error {
	resp, err := transport.StorageTransport.PatchWithAuth(GROUPSV2_GROUP, out, "application/x-protobuf", "Basic "+basicAuth(groupsV2Authorization.Username, groupsV2Authorization.Password))
	if err != nil {
		log.Errorln("[textsecure][groupsv2] Failed to encode address groupActions2:", err)
		return err
	}
	if resp.IsError() {
		return resp
	}
	log.Infoln("[textsecure][groupsv2] patch group:", resp.Status)
	if resp.IsError() {
		return resp
	}

	return nil

}
