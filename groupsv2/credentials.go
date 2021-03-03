package groupsv2

import (
	"encoding/json"
	"fmt"

	transport "github.com/signal-golang/textsecure/transport"
	log "github.com/sirupsen/logrus"
)

const (
	GROUPSV2_CREDENTIAL = "/v1/certificate/group/%d/%d"
)

type GroupCredentials struct {
	Credentials []GroupCredential `json:"credentials"`
}

type GroupCredential struct {
	Credential     []byte
	RedemptionTime int64
}

var Credentials *GroupCredentials

func GetCredentialForRedemption(day int64) *GroupCredential {
	if Credentials == nil {
		return nil
	}
	for _, credential := range Credentials.Credentials {
		if credential.RedemptionTime == day {
			return &credential
		}
	}
	return nil
}

func GetGroupAuthCredentials(startDay int64, endDay int64) error {
	log.Debugln("[textsecure] get groupCredentials", fmt.Sprintf(GROUPSV2_CREDENTIAL, startDay, endDay))
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
