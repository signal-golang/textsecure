// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.
// Groups v1 only working with tel numbers
package textsecure

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/signal-golang/textsecure/groupsv2"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	"gopkg.in/yaml.v2"
)

// Group holds group metadata.
type Group struct {
	ID      []byte
	Hexid   string
	Flags   uint32
	Name    string
	Members []string
	Avatar  []byte
}

var (
	groupDir string
	groups   = map[string]*Group{}
)

// idToHex returns the hex representation of the group id byte-slice
// to be used as both keys in the map and for naming the files.
func idToHex(id []byte) string {
	return hex.EncodeToString(id)
}

// idToPath returns the path of the file for storing a group's state
func idToPath(hexid string) string {
	return filepath.Join(groupDir, hexid)
}

// FIXME: for now using unencrypted YAML files for group state,
// should be definitely encrypted and maybe another format.

// saveGroup stores a group's state in a file.
func saveGroup(hexid string) error {
	b, err := yaml.Marshal(groups[hexid])
	if err != nil {
		return err
	}
	return ioutil.WriteFile(idToPath(hexid), b, 0600)
}

// loadGroup loads a group's state from a file.
func loadGroup(path string) error {
	_, hexid := filepath.Split(path)
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	group := &Group{}
	err = yaml.Unmarshal(b, group)
	if err != nil {
		return err
	}
	groups[hexid] = group
	return nil
}

// RemoveGroupKey removes the group key
func RemoveGroupKey(hexid string) error {
	err := os.Remove(config.StorageDir + "/groups/" + hexid)
	if err != nil {
		return err
	}
	return nil

}

// setupGroups reads all groups' state from storage.
func setupGroups() error {
	groupsv2.SetupGroups(config.StorageDir)
	groupDir = filepath.Join(config.StorageDir, "groups")
	if err := os.MkdirAll(groupDir, 0700); err != nil {
		return err
	}
	filepath.Walk(groupDir, func(path string, fi os.FileInfo, err error) error {
		if !fi.IsDir() {
			if !strings.Contains(path, "avatar") {
				loadGroup(path)
			}
		}
		return nil

	})
	return nil
}

// removeMember removes a given number from a list.
func removeMember(tel string, members []string) []string {
	for i, m := range members {
		if m == tel {
			members = append(members[:i], members[i+1:]...)
			break
		}
	}
	return members
}

// updateGroup updates a group's state based on an incoming message.
func updateGroup(gr *signalservice.GroupContext) error {
	log.Debugln("[textsecure] updateGroup ", gr.GetName())
	hexid := idToHex(gr.GetId())

	var r io.Reader
	av := gr.GetAvatar()
	buf := new(bytes.Buffer)
	if av != nil {
		att, err := handleSingleAttachment(av)
		if err != nil {
			return err
		}
		r = att.R
		buf.ReadFrom(r)
	}

	groups[hexid] = &Group{
		ID:      gr.GetId(),
		Hexid:   hexid,
		Name:    gr.GetName(),
		Members: gr.GetMembersE164(),
		Avatar:  buf.Bytes(),
	}
	return saveGroup(hexid)
}

// UnknownGroupIDError is returned when an unknown group id is encountered
type UnknownGroupIDError struct {
	id string
}

func (err UnknownGroupIDError) Error() string {
	return fmt.Sprintf("unknown group ID %s", err.id)
}

// quitGroup removes a quitting member from the local group state.
func quitGroup(src string, hexid string) error {
	gr, ok := groups[hexid]
	if !ok {
		return UnknownGroupIDError{hexid}
	}

	gr.Members = removeMember(src, gr.Members)

	return saveGroup(hexid)
}

// GroupUpdateFlag signals that this message updates the group membership or name.
var GroupUpdateFlag uint32 = 1

// GroupLeaveFlag signals that this message is a group leave message
var GroupLeaveFlag uint32 = 2

// handleGroups is the main entry point for handling the group metadata on messages.
func handleGroups(src string, dm *signalservice.DataMessage) (*Group, error) {
	gr := dm.GetGroup()
	if gr == nil {
		return nil, nil
	}
	hexid := idToHex(gr.GetId())
	log.Debugln("[textsecure] handle group", hexid, gr.GetType())
	switch gr.GetType() {
	case signalservice.GroupContext_UPDATE:
		if err := updateGroup(gr); err != nil {
			return nil, err
		}
		groups[hexid].Flags = GroupUpdateFlag
	case signalservice.GroupContext_DELIVER:
		eGr, ok := groups[hexid]
		setupGroups()
		if !ok || len(eGr.Members) == 0 || hexid == eGr.Name {
			log.Debugln("[textsecure] request update group", hexid)
			g, _ := newPartlyGroup(gr.GetId())
			g.Members = []string{src}
			RequestGroupInfo(g)
			setupGroups()
			return nil, UnknownGroupIDError{hexid}
		}
		groups[hexid].Flags = 0
	case signalservice.GroupContext_QUIT:
		if err := quitGroup(src, hexid); err != nil {
			return nil, err
		}
		groups[hexid].Flags = GroupLeaveFlag
	}

	return groups[hexid], nil
}

type groupMessage struct {
	id      []byte
	name    string
	members []string
	typ     signalservice.GroupContext_Type
}

func sendGroupHelper(hexid string, msg string, a *att, timer uint32) (uint64, error) {
	var ts uint64
	var err error
	g, ok := groups[hexid]
	if !ok {
		log.Infoln("[textsecure] sendGroupHelper unknown group id")
		return 0, UnknownGroupIDError{hexid}
	}
	// if len is 0 smth is obviously wrong
	if len(g.Members) == 0 {
		err := RemoveGroupKey(hexid)
		if err != nil {
			log.Errorln("[textsecure] sendGroupHelper", err)
		}
		setupGroups()
		log.Infoln("[textsecure] sendGroupHelper", g)
		RequestGroupInfo(g)
		return 0, fmt.Errorf("[textsecure] sendGroupHelper: need someone in the group to send you a message")
	}
	timestamp := uint64(time.Now().UnixNano() / 1000000)
	for _, m := range g.Members {
		if m != config.Tel {
			omsg := &outgoingMessage{
				destination: m,
				msg:         msg,
				attachment:  a,
				expireTimer: timer,
				timestamp:   &timestamp,
				group: &groupMessage{
					id:  g.ID,
					typ: signalservice.GroupContext_DELIVER,
				},
			}
			ts, err = sendMessage(omsg)
			if err != nil {
				log.Errorln("[textsecure] sendGroupHelper", err, m)
				return 0, err
			}
			log.Debugln("[textsecure] sendGroupHelper message to group sent", m)

		}
	}
	return ts, nil
}

// SendGroupMessage sends a text message to a given group.
func SendGroupMessage(hexid string, msg string, timer uint32) (uint64, error) {
	return sendGroupHelper(hexid, msg, nil, timer)
}

// SendGroupAttachment sends an attachment to a given group.
func SendGroupAttachment(hexid string, msg string, r io.Reader, timer uint32) (uint64, error) {
	ct, r := MIMETypeFromReader(r)
	a, err := uploadAttachment(r, ct)
	if err != nil {
		return 0, err
	}
	return sendGroupHelper(hexid, msg, a, timer)
}

// SendGroupVoiceNote sends an voice note to a group
func SendGroupVoiceNote(hexid string, msg string, r io.Reader, timer uint32) (uint64, error) {
	ct, r := MIMETypeFromReader(r)
	a, err := uploadVoiceNote(r, ct)
	if err != nil {
		return 0, err
	}
	return sendGroupHelper(hexid, msg, a, timer)
}
func newGroupID() []byte {
	id := make([]byte, 16)
	randBytes(id)
	return id
}

func newPartlyGroup(id []byte) (*Group, error) {
	hexid := idToHex(id)
	groups[hexid] = &Group{
		ID:      id,
		Hexid:   hexid,
		Name:    "",
		Members: nil,
		Avatar:  nil,
	}
	err := saveGroup(hexid)
	if err != nil {
		return nil, err
	}
	return groups[hexid], nil
}

func changeGroup(hexid, name string, members []string) (*Group, error) {
	g, ok := groups[hexid]
	if !ok {
		return nil, UnknownGroupIDError{hexid}
	}

	g.Name = name
	g.Members = append(members, config.Tel)
	saveGroup(hexid)

	return g, nil
}

func sendUpdate(g *Group) error {
	for _, m := range g.Members {
		if m != config.Tel {
			omsg := &outgoingMessage{
				destination: m,
				group: &groupMessage{
					id:      g.ID,
					name:    g.Name,
					members: g.Members,
					typ:     signalservice.GroupContext_UPDATE,
				},
			}
			_, err := sendMessage(omsg)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func newGroup(name string, members []string) (*Group, error) {
	id := newGroupID()
	hexid := idToHex(id)
	groups[hexid] = &Group{
		ID:      id,
		Hexid:   hexid,
		Name:    name,
		Members: append(members, config.Tel),
	}
	err := saveGroup(hexid)
	if err != nil {
		return nil, err
	}
	return groups[hexid], nil
}

// RequestGroupInfo updates the info for the group like members or the avatat
func RequestGroupInfo(g *Group) error {
	log.Debugln("[textsecure] request group update", g.Hexid)
	for _, m := range g.Members {
		if m != config.Tel {
			log.Debugln(m)
			omsg := &outgoingMessage{
				destination: m,
				group: &groupMessage{
					id:  g.ID,
					typ: signalservice.GroupContext_REQUEST_INFO,
				},
			}
			_, err := sendMessage(omsg)
			if err != nil {
				return err
			}
		}
	}
	if len(g.Members) == 0 {
		omsg := &outgoingMessage{
			destination: config.Tel,
			group: &groupMessage{
				id:  g.ID,
				typ: signalservice.GroupContext_REQUEST_INFO,
			},
		}
		_, err := sendMessage(omsg)
		if err != nil {
			return err
		}
	}
	return nil
}

// NewGroup creates a group and notifies its members.
// Our phone number is automatically added to members.
func NewGroup(name string, members []string) (*Group, error) {
	g, err := newGroup(name, members)
	if err != nil {
		return nil, err
	}
	return g, sendUpdate(g)
}

// UpdateGroup updates the group name and/or membership.
// Our phone number is automatically added to members.
func UpdateGroup(hexid, name string, members []string) (*Group, error) {
	g, err := changeGroup(hexid, name, members)
	if err != nil {
		return nil, err
	}
	return g, sendUpdate(g)
}

func removeGroup(id []byte) error {
	hexid := idToHex(id)
	err := os.Remove(idToPath(hexid))
	if err != nil {
		return err
	}
	return nil
}

// GetGroupById returns a group by it's id
func GetGroupById(hexID string) (*Group, error) {
	g, ok := groups[hexID]
	if !ok {
		return nil, UnknownGroupIDError{hexID}
	}
	return g, nil
}

// LeaveGroup sends a group quit message to the other members of the given group.
func LeaveGroup(hexid string) error {
	g, ok := groups[hexid]
	if !ok {
		return UnknownGroupIDError{hexid}
	}

	for _, m := range g.Members {
		if m != config.Tel {
			omsg := &outgoingMessage{
				destination: m,
				group: &groupMessage{
					id:  g.ID,
					typ: signalservice.GroupContext_QUIT,
				},
			}
			_, err := sendMessage(omsg)
			if err != nil {
				return err
			}
		}
	}
	removeGroup(g.ID)
	return nil
}
