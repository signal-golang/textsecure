package contactsDiscovery

import "encoding/base64"

var (
	cookies                            = []string{"IBMCLB-d9a02e8c-cb0e-403b-b6b8-692dafc64025=084baeb2-6331-423b-b0d4-d90dccc50c14"}
	PrivateKey                         = int8toByteArray(-72, -105, 57, 53, 89, 108, -10, 29, -108, 37, -59, -125, 12, -62, -31, 71, -60, -40, -87, -32, -110, -40, 110, 125, 44, -83, 86, -78, -68, 71, 124, 114)
	PublicKey                          = int8toByteArray(17, 106, -95, -59, 60, 119, 57, -76, 5, 66, 24, -12, 91, 27, 114, 14, -127, 113, -111, 17, -23, 29, -97, -28, 43, -86, 20, 105, 57, -110, -33, 46)
	TestMultiRemoteAttestationResponse = &MultiRemoteAttestationResponse{
		Attestations: map[string]*RemoteAttestationResponse{
			"bba07fc7-5d44-40fd-b63c-3909949f45ce": {
				ServerEphemeralPublic: fromBase64("73zKT2UeMHxbhH9PgZwyFijQmlOqTMpCP3YAgxreEkg="),
				ServerStaticPublic:    fromBase64("Jx35KnXMX5sQPFsr+eUMvt34TuwHAG79krMIwI4lFwc="),
				Quote:                 fromBase64("AgAAAAAMAAALAAoAAAAAAPiLWcRSSA3shraxepsGV9pLMhG9gyJav4Ie3c7ley2tERECBv+ABwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAHAAAAAAAAAMmOAKTj/5d6Vq/v5zYqJ+SWHk8Z4hH+v7sZuJfmuAsVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADrzm117Qj8NlEllyDkV4Pae4UgsPjgVXtAA5UsG90gVgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAnHfkqdcxfmxA8Wyv55Qy+3fhO7AcAbv2SswjAjiUXBwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAAK4wooAyCrbG3h0i3Vlu4JX/v+DTO7TJmNyIfHVMM4CWT/+3nOQSxSqzgzQmMn3+x2VuXrGwV21wxxHDIahPVdzJFkT+Jlj9fscEtUCyjFzweBd1WC5O1iHVOdjBVJPkLHyc6UU+vvuF9HhdQi6irqmGPOT4Q8oj0DkmvGAma9n8iJBPdXVqHYd2tQaCcF4PaD3w8Z/v8qrj3AGpiI1NGlREYKbgNhdBKsxtdDe+sIKN4DgTQSimxn2vkq44vDNugyFfcujK2Efmqo2kk0uUk6n/n4pNEC13WQSF9BOXZsOADc9CdgTMRI2/rHw2vHQVPCcLAEmJqiGroj7/KpYD5rv3SPNQvYPb6JfQtZpz8PLzneH4Ipb4e9WuuKMcr6znNP/XdDqoJtsT+vsCUmgBAADVU0OZf00jshCwFr737gtMOCZOfRG32ltygz89IJAui7oA9nZ+vozP7Z3iGJcl/sMsDK3hoV8k3dQb6ed9ychf6fIlDibzW8PE3Wh2DluXmKbvHOV8Ie3epq9m7ufRWNuz5vQMsIbja1fw8L/NsUwArWTtB4bFeCNuYKZk3k6W77JRCh5724A7/ukPsgw8SBoHIGvSIUUCAA2cH28EEEA4zW28TBUiprVhX+hRemaoR2TpxHURI0w4f2IrqL/YUSNuDrgSWS6g4G0tJQ9wzWDesO2kpGhAy3a0Y0ytc2OKiIyAvnV1uftb3FOl4pN2J3fAy3YCFrsQhe7+x5HyESbrAectdbW55LW5+QqJ3ZRVM9wNGTTLyzyzLJUC13rOwM8gFczU9erFIC+mlIcb7tBdZSpYhFqxunpRB35fQOgsCciopqcOvjgouCc7Fldi44GzfTuHJJ979wVepEKgX36yh9ZLgllfMxrmwy5wzkDxFzZstNUydbjg"),
				Iv:                    fromBase64("AAAAAAAAAAAAAAAA"),
				Ciphertext:            fromBase64("pOdFRjBgVdKfFxb5vK0xKc/ftNpO35NmTQ4h7EIOR0dy4KkL"),
				Tag:                   fromBase64("5mkps6ew2BQjs3FSIbJyGA=="),
				Signature:             "GtuOVnlj27+rNjnQ996v4wrvCPayiw2lxNq62EMysw3xA+eW0H4K1jkwbLPXJQVyC+pfUhcu4rBe7TgX++793HkwXaqglysAiGgVCf/T252oe/UqPsN6nB413boWOREj9O+ppy71L6BMJfV9UsYtowizrWzxeTvqwbKlA7cWUT7C3MWlCSEl29JapzlB3QhlvCTm/W42bQLWFKT5WXbq92C2iV/hrEIJfzWx/ZF+yhMY9CLWn6m2+6KXRsCiTa1SrxGT9NiZKMKUaKDEfx+aE0uVKDWYCFCN2Qwij389C54hYhxCaBF1IyIB1Uq2G+DCboj4SPYrbD1JSCojLjaYlg==",
			},
		},
	}
	testephemeralToEphemeral = int8toByteArray32(80, -107, 26, -102, 23, 71, 16, -24, 99, -56, 90, -95, 52, 119, -50, 51, 94, -70, 98, 52, -85, 70, -50, 126, 88, 40, -89, -93, 8, 99, 111, 71)
	testephemeralToStatic    = int8toByteArray32(22, -26, -85, 42, -61, 16, -24, -110, 103, 71, 32, -87, -98, -67, 82, 118, 15, -112, -21, 51, -108, -122, -82, 49, -26, -39, 36, -36, -71, -71, -118, 15)
	testmasterSecret         = int8toByteArray(80, -107, 26, -102, 23, 71, 16, -24, 99, -56, 90, -95, 52, 119, -50, 51, 94, -70, 98, 52, -85, 70, -50, 126, 88, 40, -89, -93, 8, 99, 111, 71, 22, -26, -85, 42, -61, 16, -24, -110, 103, 71, 32, -87, -98, -67, 82, 118, 15, -112, -21, 51, -108, -122, -82, 49, -26, -39, 36, -36, -71, -71, -118, 15)
	testpublicKeys           = int8toByteArray(17, 106, -95, -59, 60, 119, 57, -76, 5, 66, 24, -12, 91, 27, 114, 14, -127, 113, -111, 17, -23, 29, -97, -28, 43, -86, 20, 105, 57, -110, -33, 46, -17, 124, -54, 79, 101, 30, 48, 124, 91, -124, 127, 79, -127, -100, 50, 22, 40, -48, -102, 83, -86, 76, -54, 66, 63, 118, 0, -125, 26, -34, 18, 72, 39, 29, -7, 42, 117, -52, 95, -101, 16, 60, 91, 43, -7, -27, 12, -66, -35, -8, 78, -20, 7, 0, 110, -3, -110, -77, 8, -64, -114, 37, 23, 7)
	testclientkey            = int8toByteArray(-26, 66, -52, 30, 87, 81, -46, -81, 39, -12, 16, -57, 25, -38, -19, 121, -20, -36, -78, 8, 42, 71, 65, 123, -88, 114, 38, 94, 48, -93, -89, -113)
	testserverkey            = int8toByteArray(92, -102, -112, -16, -12, 50, 51, 38, 20, -51, 93, -28, 74, 60, 77, 47, 16, -17, -105, 122, -126, -91, -1, 102, -83, -61, 84, 125, 81, 125, -85, 35)
	testrequestid            = int8toByteArray(70, -29, -3, 98, 35, 20, 13, -51, 124, -94, 106, 48, 69, -103, 62, -54, 113, -51, 2, 23, 80, -119, -125, 17, -4, 66, -45, -28, -123, -84, 30, -35, 44, 60, 70, -112)
)

func fromBase64(encoded string) []byte {
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	return decoded
}

func int8toByteArray(in ...int8) []byte {
	out := make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		out[i] = int8toByte(in[i])
	}
	return out
}
func int8toByteArray32(in ...int8) [32]byte {
	out := [32]byte{}
	for i := 0; i < len(in); i++ {
		out[i] = int8toByte(in[i])
	}
	return out
}
func int8toByte(i int8) byte {
	return byte(i)
}
