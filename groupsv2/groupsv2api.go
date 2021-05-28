package groupsv2

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	zkgroup "github.com/nanu-c/zkgroup"
	transport "github.com/signal-golang/textsecure/transport"
	log "github.com/sirupsen/logrus"
)

type GroupsV2Authorization struct {
	Username string
	Password string
}

func NewGroupsV2AuthorizationForGroup(uuid []byte, hexid string) (*GroupsV2Authorization, error) {
	group := groupsV2[hexid]
	groupSecretParams, err := zkgroup.NewGroupSecretParams(group.MasterKey)
	if err != nil {
		log.Warnln("[textsecure] NewGroupsV2AuthorizationForGroup", err.Error())

	}

	return NewGroupsV2Authorization(uuid, groupSecretParams)
}

func NewGroupsV2Authorization(uuid []byte, groupSecretParams zkgroup.GroupSecretParams) (*GroupsV2Authorization, error) {
	publicGroupParams, err := groupSecretParams.PublicParams()
	today := time.Now().Unix() / 86400

	authCredentialResponse, err := zkgroup.NewAuthCredentialResponse(GetCredentialForRedemption(today).Credential)
	if err != nil {
		log.Warnln("[textsecure] NewGroupsV2AuthorizationForGroup2", err.Error())

	}
	zkGroupServerPublicParams, _ := base64.StdEncoding.DecodeString(ZKGROUP_SERVER_PUBLIC_PARAMS)
	serverPublicParams, err := zkgroup.NewServerPublicParams(zkGroupServerPublicParams)
	if err != nil {
		log.Warnln("[textsecure] NewGroupsV2AuthorizationForGroup1", err.Error())

	}
	clientZkAuthOperations, err := zkgroup.NewClientZkAuthOperations(serverPublicParams)
	if err != nil {
		log.Warnln("[textsecure] NewGroupsV2AuthorizationForGroup2", err.Error())

	}
	authCredential, err := clientZkAuthOperations.ReceiveAuthCredential(uuid, (uint32)(today), authCredentialResponse)
	if err != nil {
		log.Warnln("[textsecure] NewGroupsV2AuthorizationForGroup3", err.Error(), uuid)
		return nil, err
	}
	authCredentialPresentation, err := clientZkAuthOperations.CreateAuthCredentialPresentation(groupSecretParams, authCredential)
	if authCredentialPresentation == nil {

		log.Debugln("[textsecure] getting public params", err)
		return nil, fmt.Errorf("auth Credentials not found")
	}
	return &GroupsV2Authorization{
		Username: idToHex(publicGroupParams),
		Password: idToHex(authCredentialPresentation),
	}, nil
}

type AuthCredentials struct {
	username string `json:"username"`
	password string `json:"password"`
}

func (a *AuthCredentials) AsBasic() string {
	usernameAndPassword := a.username + ":" + a.password
	encoded := base64.StdEncoding.EncodeToString([]byte(usernameAndPassword))
	return "Basic " + encoded
}

func getCredendtails(path string) (*AuthCredentials, error) {
	resp, err := transport.Transport.Get(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(resp.Body)
	var a AuthCredentials
	dec.Decode(&a)

	return &a, nil

}
func getGroupJoinInfo(groupSecretParams, groupLinkPassword []byte, groupsV2AuthorizationString string) {

}
