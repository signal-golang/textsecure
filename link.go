package textsecure

import (
	"time"

	log "github.com/sirupsen/logrus"
)

var code2 string

// AddNewLinkedDevice adds a new signal desktop client
func AddNewLinkedDevice(uuid string, publicKey string) error {
	log.Printf("AddNewLinkedDevice")
	if code2 == "" {
		code, err := getNewDeviceVerificationCode()
		if err != nil {
			return err
		}
		code2 = code
	}

	err := addNewDevice(uuid, publicKey, code2)
	if err != nil {
		log.Errorf(err.Error())
		return err
	}
	timer := time.NewTimer(10 * time.Second)
	go func() {
		<-timer.C
		code2 = ""
	}()
	return nil
}
