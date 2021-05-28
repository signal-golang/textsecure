package helpers

func HexToUUID(id string) string {
	if len(id) != 32 {
		return id
	}
	msbHex := id[:16]
	lsbHex := id[16:]
	return msbHex[:8] + "-" + msbHex[8:12] + "-" + msbHex[12:] + "-" + lsbHex[:4] + "-" + lsbHex[4:]
}
