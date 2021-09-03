package helpers

import (
	"encoding/base64"
	"strings"
)

// Base64-encodes without padding the result
func Base64EncWithoutPadding(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	return strings.TrimRight(s, "=")
}

// Base64-decodes a non-padded string
func Base64DecodeNonPadded(s string) ([]byte, error) {
	if len(s)%4 != 0 {
		s = s + strings.Repeat("=", 4-len(s)%4)
	}
	return base64.StdEncoding.DecodeString(s)
}
