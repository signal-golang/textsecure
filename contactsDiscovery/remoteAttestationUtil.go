package contactsDiscovery

import (
	"encoding/json"
	"fmt"

	axolotl "github.com/signal-golang/textsecure/axolotl"
	"github.com/signal-golang/textsecure/transport"

	log "github.com/sirupsen/logrus"
)

const REMOTE_ATTESTATION_REQUEST = "/v1/attestation/%s"

type RemoteAttestation struct {
	RequestId []byte
	Keys      RemoteAttestationKeys
	Cookies   []string
}
type RemoteAttestationRequest struct {
	ClientPublic []byte `json:"clientPublic"`
}

type RemoteAttestationResponse struct {
	ServerEphemeralPublic []byte
	ServerStaticPublic    []byte
	Quote                 []byte
	Iv                    []byte
	Ciphertext            []byte
	Tag                   []byte
	Signature             string
	Certificates          string
	SignatureBody         string
}
type MultiRemoteAttestationResponse struct {
	Attestations []RemoteAttestationResponse
}
type RemoteAttestationKeys struct {
	ClientKey []byte
	ServerKey []byte
}

func (r *RemoteAttestation) GetAndVerifyMultiRemoteAttestation(
	// PushServiceSocket.ClientSet clientSet,
	// KeyStore iasKeyStore,
	enclaveName string,
	authorization string) ([]RemoteAttestation, error) {

	keyPair := axolotl.NewECKeyPair()
	publicKey := keyPair.PublicKey.Key()
	remoteAttestationRequest := RemoteAttestationRequest{
		ClientPublic: publicKey[:],
	}

	body, err := json.Marshal(remoteAttestationRequest)
	if err != nil {
		return nil, err
	}

	log.Debugln(string(body))
	resp, err := transport.DirectoryTransport.PutJSONWithAuth(
		fmt.Sprintf(REMOTE_ATTESTATION_REQUEST, enclaveName),
		body,
		authorization,
	)
	multiRemoteAttestationResponse := &MultiRemoteAttestationResponse{}
	dec := json.NewDecoder(resp.Body)

	err = dec.Decode(&multiRemoteAttestationResponse)
	if err != nil {
		return nil, err
	}
	log.Debugln(resp, err)
	if len(multiRemoteAttestationResponse.Attestations) < 1 || len(multiRemoteAttestationResponse.Attestations) > 3 {
		return nil, fmt.Errorf("Incorrect number of attestations: " + string(len(multiRemoteAttestationResponse.Attestations)))
	}
	assestations := []RemoteAttestation{}

	for _, remoteAttestationResponse := range multiRemoteAttestationResponse.Attestations {
		assestations = append(assestations, validateAndBuildRemoteAttestation(remoteAttestationResponse,
			resp.Cookies,
			// KeyStore,
			keyPair,
			enclaveName,
		),
		)
	}

	return nil, nil
}

func validateAndBuildRemoteAttestation(
	remoteAttestation RemoteAttestationResponse,
	cookies []string,
	// keystore,
	keyPair *axolotl.ECKeyPair,
	enclaveName string,
) RemoteAttestation {
	keys := remoteAttestationKeys(keyPair, remoteAttestation.ServerEphemeralPublic, remoteAttestation.ServerStaticPublic)
	requestId := getRequestId(keys, remoteAttestation)

	// Quote                 quote     = new Quote(response.getQuote()); -> quote.go

	// byte[]                requestId = RemoteAttestationCipher.getRequestId(keys, response);

	// RemoteAttestationCipher.verifyServerQuote(quote, response.getServerStaticPublic(), mrenclave);

	// RemoteAttestationCipher.verifyIasSignature(iasKeyStore, response.getCertificates(), response.getSignatureBody(), response.getSignature(), quote);
	return RemoteAttestation{
		Keys: keys,
		// Quote:,
		RequestId: requestId,
	}

}
func getRequestId(keys RemoteAttestationKeys, response RemoteAttestationResponse) []byte {
	// return AESCipher.decrypt(keys.ServerKey, response.Iv, response.Ciphertext, response.Tag)
	return []byte{}
}

// static byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] tag) throws InvalidCiphertextException {
//     try {
//       Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
//       cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LENGTH_BITS, iv));

//       return cipher.doFinal(ByteUtil.combine(ciphertext, tag));
//     } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException e) {
//       throw new AssertionError(e);
//     } catch (InvalidKeyException | BadPaddingException e) {
//       throw new InvalidCiphertextException(e);
//     }
//   }
func remoteAttestationKeys(keyPair *axolotl.ECKeyPair, serverPublicEphemerl []byte, serverPublicStatic []byte) RemoteAttestationKeys {
	// public RemoteAttestationKeys(ECKeyPair keyPair, byte[] serverPublicEphemeral, byte[] serverPublicStatic) throws InvalidKeyException {
	//     byte[] ephemeralToEphemeral = Curve.calculateAgreement(ECPublicKey.fromPublicKeyBytes(serverPublicEphemeral), keyPair.getPrivateKey());
	//     byte[] ephemeralToStatic    = Curve.calculateAgreement(ECPublicKey.fromPublicKeyBytes(serverPublicStatic), keyPair.getPrivateKey());

	//     byte[] masterSecret = ByteUtil.combine(ephemeralToEphemeral, ephemeralToStatic                          );
	//     byte[] publicKeys   = ByteUtil.combine(keyPair.getPublicKey().getPublicKeyBytes(), serverPublicEphemeral, serverPublicStatic);

	//     HKDFv3 generator = new HKDFv3();
	//     byte[] keys      = generator.deriveSecrets(masterSecret, publicKeys, null, clientKey.length + serverKey.length);

	//     System.arraycopy(keys, 0, clientKey, 0, clientKey.length);
	//     System.arraycopy(keys, clientKey.length, serverKey, 0, serverKey.length);

	return RemoteAttestationKeys{}

}
