package utils

import (
	"os"
	"time"

	uuid "github.com/satori/go.uuid"
)

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
func UUIDStr(uuid_ba []byte) (string, error) {
	u, err := uuid.FromBytes(uuid_ba)
	if err != nil {
		return "", err
	}
	return u.String(), err
}
func CurrentTimeMillis() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}
func Max(a uint32, b uint32) uint32 {
	if a >= b {
		return a
	}
	return b

}
