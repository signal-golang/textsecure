package transport

import (
	"encoding/base64"
	"encoding/json"

	log "github.com/sirupsen/logrus"

	"golang.org/x/text/encoding/charmap"
)

var DIRECTORY_AUTH_PATH = "/v1/directory/auth"

// AuthCredentials holds the credentials for the websocket connection
type AuthCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *AuthCredentials) AsBasic() string {
	usernameAndPassword := a.Username + ":" + a.Password
	dec := charmap.Windows1250.NewDecoder()
	out, _ := dec.String(usernameAndPassword)
	encoded := base64.StdEncoding.EncodeToString([]byte(out))
	return "Basic " + encoded
}

func GetCredendtails(path string) (*AuthCredentials, error) {
	if path == "" {
		path = DIRECTORY_AUTH_PATH
	}
	resp, err := Transport.Get(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(resp.Body)
	var a AuthCredentials
	dec.Decode(&a)
	log.Debugln("[textsecure] getCredentials ")
	return &a, nil

}
