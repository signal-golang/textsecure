package textsecure

import "github.com/signal-golang/textsecure/config"

// SetUsername sets the profile name
func SetUsername(name string) {
	config.ConfigFile.Name = name
	saveConfig(config.ConfigFile)
}

func RefreshOwnProfile() {

}
