// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package contacts

import (
	"fmt"
	"io/ioutil"

	signalservice "github.com/signal-golang/textsecure/protobuf"
	log "github.com/sirupsen/logrus"

	"gopkg.in/yaml.v2"
)

// Contact contains information about a contact.
type Contact struct {
	UUID                 string
	Tel                  string
	ProfileKey           []byte
	ProfileKeyCredential []byte
	IdentityKey          []byte
	Name                 string
	Username             string
	AvatarImg            []byte
	Avatar               []byte
	HasAvatar            bool
	Color                string
	Blocked              bool
	Verified             *signalservice.Verified
	ExpireTimer          uint32
	InboxPosition        uint32
	Archived             bool
	Certificate          []byte
	Registered           bool
}

func (c *Contact) GetProfileKey() []byte {
	return c.ProfileKey
}

type yamlContacts struct {
	Contacts []Contact
}

var (
	contactsFile string
	Contacts     = map[string]Contact{}
)

// LoadContacts reads a YAML contacts file
func LoadContacts(contactsYaml *yamlContacts) {
	for _, c := range contactsYaml.Contacts {
		if c.UUID != "" && c.UUID != "0" && (c.UUID[0] != 0 || c.UUID[len(c.UUID)-1] != 0) {
			Contacts[c.UUID] = c

		} else {
			Contacts[c.Tel] = c
		}
	}
}

var filePath string

// ReadContacts loads the contacts yaml file and pareses it
func ReadContacts(fileName string) ([]Contact, error) {
	log.Debug("[textsecure] read contacts from ", fileName)
	b, err := ioutil.ReadFile(fileName)
	filePath = fileName
	if err != nil {
		return nil, err
	}
	contactsYaml := &yamlContacts{}
	err = yaml.Unmarshal(b, contactsYaml)
	if err != nil {
		return nil, err
	}
	LoadContacts(contactsYaml)
	return contactsYaml.Contacts, nil
}

// WriteContacts saves a list of contacts to a file
func WriteContacts(filename string, contacts []Contact) error {
	log.Debug("[textsecure] write contacts ", len(contacts))

	c := &yamlContacts{contacts}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, b, 0600)
}

// WriteContactsToPath saves a list of contacts to a file at the standard location
func WriteContactsToPath() error {
	c := contactsToYaml()
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, b, 0600)
}
func contactsToYaml() *yamlContacts {
	c := &yamlContacts{}
	for _, co := range Contacts {
		c.Contacts = append(c.Contacts, co)
	}
	return c
}

func updateContact(c *signalservice.ContactDetails) error {
	log.Debugln("[textsecure] updateContact ", c.GetUuid())

	// var r io.Reader
	// av := c.GetAvatar()
	// buf := new(bytes.Buffer)
	// if av != nil {
	// 	att, err := handleProfileAvatar(av, c.GetProfileKey())
	// 	if err != nil {
	// 		return err
	// 	}
	// 	r = att.R
	// 	buf.ReadFrom(r)
	// }
	// avatar, _ := ioutil.ReadAll(buf)

	Contacts[c.GetUuid()] = Contact{
		Tel:  c.GetNumber(),
		UUID: c.GetUuid(),
		Name: c.GetName(),
		// Avatar:        avatar,
		HasAvatar:     false,
		Color:         c.GetColor(),
		Verified:      c.GetVerified(),
		ProfileKey:    c.GetProfileKey(),
		Blocked:       c.GetBlocked(),
		ExpireTimer:   c.GetExpireTimer(),
		InboxPosition: c.GetInboxPosition(),
		Archived:      c.GetArchived(),
	}
	// log.Debugln("[textsecure] avatar", c.GetAvatar())
	return WriteContactsToPath()
}

func HandleContacts(src string, dm *signalservice.DataMessage) ([]*signalservice.DataMessage_Contact, error) {
	cs := dm.GetContact()
	if cs == nil {
		return nil, nil
	}

	for _, c := range cs {

		log.Debugln("[textsecure] handle Contact", c.GetName())
	}
	return nil, nil
}

func UpdateProfileKey(src string, profileKey []byte) error {
	log.Println("[textsecure] update profile key", src)
	if contact, ok := Contacts[src]; ok {
		contact.ProfileKey = profileKey
		Contacts[src] = contact
		return WriteContactsToPath()
	}
	return fmt.Errorf("Contact to update not found %s", src)
}

func GetContact(uuid string) Contact {
	return Contacts[uuid]
}
