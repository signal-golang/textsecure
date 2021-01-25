// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"bytes"
	"io"
	"io/ioutil"

	signalservice "github.com/signal-golang/textsecure/protobuf"
	log "github.com/sirupsen/logrus"

	"gopkg.in/yaml.v2"
)

// Contact contains information about a contact.
type Contact struct {
	UUID          string
	Tel           string
	ProfileKey    []byte
	IdentityKey   []byte
	Name          string
	Username      string
	Avatar        []byte
	Color         string
	Blocked       bool
	Verified      *signalservice.Verified
	ExpireTimer   uint32
	InboxPosition uint32
	Archived      bool
}

type yamlContacts struct {
	Contacts []Contact
}

var (
	contactsFile string
	contacts     = map[string]Contact{}
)

// ReadContacts reads a YAML contacts file
func loadContacts(contactsYaml *yamlContacts) {
	for _, c := range contactsYaml.Contacts {
		if c.UUID != "" && c.UUID != "0" && (c.UUID[0] != 0 || c.UUID[len(c.UUID)-1] != 0) {
			contacts[c.UUID] = c

		} else {
			contacts[c.Tel] = c
		}
	}
}

var filePath string

// ReadContacts loads the contacts yaml file and pareses it
func ReadContacts(fileName string) ([]Contact, error) {
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
	loadContacts(contactsYaml)
	return contactsYaml.Contacts, nil
}

// WriteContacts saves a list of contacts to a file
func WriteContacts(filename string, contacts []Contact) error {
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
	for _, co := range contacts {
		c.Contacts = append(c.Contacts, co)
	}
	return c
}

func updateContact(c *signalservice.ContactDetails) error {
	log.Debugln("[textsecure] updateContact ", c.GetUuid())

	var r io.Reader
	av := c.GetAvatar()
	buf := new(bytes.Buffer)
	if av != nil {
		att, err := handleProfileAvatar(av, c.GetProfileKey())
		if err != nil {
			return err
		}
		r = att.R
		buf.ReadFrom(r)
	}
	avatar, _ := ioutil.ReadAll(buf)

	contacts[c.GetUuid()] = Contact{
		Tel:           c.GetNumber(),
		UUID:          c.GetUuid(),
		Name:          c.GetName(),
		Avatar:        avatar,
		Color:         c.GetColor(),
		Verified:      c.GetVerified(),
		ProfileKey:    c.GetProfileKey(),
		Blocked:       c.GetBlocked(),
		ExpireTimer:   c.GetExpireTimer(),
		InboxPosition: c.GetInboxPosition(),
		Archived:      c.GetArchived(),
	}
	log.Debugln(c.GetAvatar(), buf)
	return WriteContactsToPath()
}

func handleContacts(src string, dm *signalservice.DataMessage) ([]*signalservice.DataMessage_Contact, error) {
	cs := dm.GetContact()
	if cs == nil {
		return nil, nil
	}

	for _, c := range cs {

		log.Debugln("[textsecure] handle Contact", c.GetName())
	}
	return nil, nil
}

// SyncContacts syncs the contacts
func SyncContacts() error {
	var t signalservice.SyncMessage_Request_Type
	t = signalservice.SyncMessage_Request_CONTACTS
	omsg := &signalservice.SyncMessage{
		Request: &signalservice.SyncMessage_Request{
			Type: &t,
		},
	}
	_, err := sendSyncMessage(omsg, nil)
	if err != nil {
		return err
	}

	return nil
}
