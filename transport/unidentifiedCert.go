package transport

import (
	"encoding/json"

	log "github.com/sirupsen/logrus"
)

type SenderCertificate struct {
	Certificate []byte `json:"certificate"`
}

var (
	SENDER_CERTIFICATE_PATH = "/v1/certificate/delivery"
)

func GetSenderCertificate() (*SenderCertificate, error) {
	log.Infoln("[textsecure] Getting SenderCertificate")
	certificates := &SenderCertificate{}

	resp, err := Transport.Get(SENDER_CERTIFICATE_PATH)
	if err != nil {
		return nil, err
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&certificates)
	if err != nil {
		return certificates, nil
	}

	return certificates, nil
}
