package groupsv2

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	signalservice "github.com/signal-golang/textsecure/protobuf"
	transport "github.com/signal-golang/textsecure/transport"
	"google.golang.org/protobuf/proto"

	log "github.com/sirupsen/logrus"
)

const (
	GROUPSV2_CREDENTIAL = "/v1/certificate/group/%d/%d"
	GROUPSV2_TOKEN      = "/v1/groups/token"
)

type GroupCredentials struct {
	Credentials []GroupCredential `json:"credentials"`
}

type GroupCredential struct {
	Credential     []byte
	RedemptionTime int64
}
type GroupExternalCredential struct {
	Token []byte `json:"token"`
}

var Credentials *GroupCredentials

func getToday() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond) / (1000 * 60 * 60 * 24)
}

func GetCredentialForRedemption(day int64) (*GroupCredential, error) {
	if Credentials == nil {
		today := getToday()
		err := GetGroupAuthCredentials(today, today+7)
		if err != nil {
			log.Errorln("[textsecure] get groupCredentials ", err)
			return nil, err
		}
	}
	for _, credential := range Credentials.Credentials {
		if credential.RedemptionTime == day {
			return &credential, nil
		}
	}
	return nil, fmt.Errorf("failed to get group credentials")
}

func GetCredentialForToday() (*GroupCredential, error) {

	today := getToday()
	credential, err := GetCredentialForRedemption(today)
	if err != nil {
		return nil, err
	}
	return credential, nil
}

func GetGroupAuthCredentials(startDay int64, endDay int64) error {
	log.Debugln("[textsecure][groupsv2] get groupCredentials")
	resp, err := transport.Transport.Get(fmt.Sprintf(GROUPSV2_CREDENTIAL, startDay, endDay))
	if err != nil {
		return err
	}
	if resp.IsError() {
		return resp
	}
	dec := json.NewDecoder(resp.Body)
	var response GroupCredentials
	dec.Decode(&response)
	Credentials = &response
	return nil
}

func GetGroupExternalCredential(credential *GroupCredential) (*signalservice.GroupExternalCredential, error) {
	log.Debugln("[textsecure][groupsv2] get groupExternalCredentials")
	resp, err := transport.Transport.Get(GROUPSV2_TOKEN)
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		return nil, resp
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var response signalservice.GroupExternalCredential
	err = proto.Unmarshal(data, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}
