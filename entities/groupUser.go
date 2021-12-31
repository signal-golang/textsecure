package entities

import (
	"bytes"
)

type GroupUser struct {
	UserCiphertext []byte
	GroupPublicKey []byte
	GroupId        []byte
	StrGroupId     string
	StrUserUUId    string
}

func (user *GroupUser) IsMember(uuid, groupPublicKey []byte) bool {
	f1 := bytes.Equal(user.GroupPublicKey, groupPublicKey)
	f2 := bytes.Equal(user.UserCiphertext, uuid)
	return f1 && f2

}
