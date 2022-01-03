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
	ProfileKeyCredential      []byte              `yaml:"profileKeyCredential"`      // The profile key is used in many places to encrypt the avatar, name etc and also in groupsv2 context
	Name                      string              `yaml:"name"`                      // The username
	UnidentifiedAccessKey     []byte              `yaml:"unidentifiedAccessKey"`     // The access key for unidentified users
	Certificate               []byte              `yaml:"certificate"`               // The access key for unidentified users
	CrayfishSupport           bool                `yaml:"crayfishSupport"`
	Group                     struct {
		MaxGroupSize                   int
		MaxGroupTitleLengthBytes       int
		MaxGroupDescriptionLengthBytes int
		ExternalServiceSecret          string
	} // weather the client uses crayfish or not
}

const (
	ZKGROUP_SERVER_PUBLIC_PARAMS = "AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGvCoKxGwgKgE5XyJ+nNKlyHHOLb6N1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQFj5ObDjcKMZf2Jm2Ae69x+ikU5gBXsRmoF94GXQ=="
	SERVICE_REFLECTOR_HOST       = "europe-west1-signal-cdn-reflector.cloudfunctions.net"
	SIGNAL_CDN_URL               = "https://cdn.signal.org"
	SIGNAL_CDN2_URL              = "https://cdn2.signal.org"
	ATTACHMENT_ID_DOWNLOAD_PATH  = "/attachments/%d"
	ATTACHMENT_KEY_DOWNLOAD_PATH = "/attachments/%s"
	AllocateAttachmentPath       = "/v1/attachments/"
)

// AccountCapabilities describes what functions axolotl supports
type AccountCapabilities struct {
	Gv2               bool `json:"gv2" yaml:"gv2"`
	SenderKey         bool `json:"senderKey" yaml:"senderKey"`
	AnnouncementGroup bool `json:"announcementGroup" yaml:"announcementGroup"`
	ChangeNumber      bool `json:"changeNumber" yaml:"changeNumber"`
	Gv1Migration      bool `json:"gv1-migration" yaml:"gv1-migration"`
}

var (
	ConfigFile *Config
)
