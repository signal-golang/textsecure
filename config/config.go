package config

// Config holds application configuration settings
type Config struct {
	Tel                       string              `yaml:"tel"` // Our telephone number
	UUID                      string              `yaml:"uuid" default:"notset"`
	Server                    string              `yaml:"server"`                    // The TextSecure server URL
	RootCA                    string              `yaml:"rootCA"`                    // The TLS signing certificate of the server we connect to
	ProxyServer               string              `yaml:"proxy"`                     // HTTP Proxy URL if one is being used
	VerificationType          string              `yaml:"verificationType"`          // Code verification method during registration (SMS/VOICE/DEV)
	StorageDir                string              `yaml:"storageDir"`                // Directory for the persistent storage
	UnencryptedStorage        bool                `yaml:"unencryptedStorage"`        // Whether to store plaintext keys and session state (only for development)
	StoragePassword           string              `yaml:"storagePassword"`           // Password to the storage
	LogLevel                  string              `yaml:"loglevel"`                  // Verbosity of the logging messages
	UserAgent                 string              `yaml:"userAgent"`                 // Override for the default HTTP User Agent header field
	AlwaysTrustPeerID         bool                `yaml:"alwaysTrustPeerID"`         // Workaround until proper handling of peer reregistering with new ID.
	AccountCapabilities       AccountCapabilities `yaml:"accountCapabilities"`       // Account Attrributes are used in order to track the support of different function for signal
	DiscoverableByPhoneNumber bool                `yaml:"discoverableByPhoneNumber"` // If the user should be found by his phone number
	ProfileKey                []byte              `yaml:"profileKey"`                // The profile key is used in many places to encrypt the avatar, name etc and also in groupsv2 context
	Name                      string              `yaml:"name"`
}

// AccountCapabilities describes what functions axolotl supports
type AccountCapabilities struct {
	UUID         bool `json:"uuid" yaml:"uuid"`
	Gv2          bool `json:"gv2-3" yaml:"gv2"`
	Storage      bool `json:"storage" yaml:"storage"`
	Gv1Migration bool `json:"gv1-migration" yaml:"gv1-migration"`
}

var (
	ConfigFile *Config
)
