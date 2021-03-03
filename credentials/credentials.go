package credentials

type GroupCredentials struct {
	Credentials []GroupCredential `json:"credentials"`
}

type GroupCredential struct {
	Credential     []byte
	RedemptionTime int64
}

var Credentials *GroupCredentials

func GetCredentialForRedemption(day int64) *GroupCredential {
	if Credentials == nil {
		return nil
	}
	for _, credential := range Credentials.Credentials {
		if credential.RedemptionTime == day {
			return &credential
		}
	}
	return nil
}
