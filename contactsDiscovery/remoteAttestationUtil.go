package contactsDiscovery

import (
	"encoding/json"
	"fmt"

	axolotl "github.com/signal-golang/textsecure/axolotl"
	textsecureCrypto "github.com/signal-golang/textsecure/crypto"
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
	ServerEphemeralPublic []byte `json:"serverEphemeralPublic"`
	ServerStaticPublic    []byte `json:"serverStaticPublic"`
	Quote                 []byte `json:"quote"`
	Iv                    []byte `json:"iv"`
	Ciphertext            []byte `json:"ciphertext"`
	Tag                   []byte `json:"tag"`
	Signature             string `json:"signature"`
	Certificates          string `json:"certificates"`
	SignatureBody         string `json:"signatureBody"`
}
type MultiRemoteAttestationResponse struct {
	Attestations map[string]*RemoteAttestationResponse `json:"attestations"`
}
type RemoteAttestationKeys struct {
	ClientKey []byte
	ServerKey []byte
}

func (r *RemoteAttestation) GetAndVerifyMultiRemoteAttestation(
	// PushServiceSocket.ClientSet clientSet,
	// KeyStore iasKeyStore,
	enclaveName string,
	authorization string) (map[string]*RemoteAttestation, error) {
	log.Debugln("[textsecure] GetAndVerifyMultiRemoteAttestation")

	keyPair := axolotl.NewECKeyPair()
	publicKey := keyPair.PublicKey.Key()
	remoteAttestationRequest := RemoteAttestationRequest{
		ClientPublic: publicKey[:],
	}

	body, err := json.Marshal(remoteAttestationRequest)
	if err != nil {
		return nil, err
	}

	resp, err := transport.DirectoryTransport.PutJSONWithAuth(
		fmt.Sprintf(REMOTE_ATTESTATION_REQUEST, enclaveName),
		body,
		authorization,
	)
	multiRemoteAttestationResponse := &MultiRemoteAttestationResponse{}
	dec := json.NewDecoder(resp.Body)
	log.Debugln(resp)

	err = dec.Decode(&multiRemoteAttestationResponse)
	if err != nil {
		return nil, err
	}
	if len(multiRemoteAttestationResponse.Attestations) < 1 || len(multiRemoteAttestationResponse.Attestations) > 3 {
		return nil, fmt.Errorf("Incorrect number of attestations: " + fmt.Sprint(len(multiRemoteAttestationResponse.Attestations)))
	}
	assestations := map[string]*RemoteAttestation{}

	for _, remoteAttestationResponse := range multiRemoteAttestationResponse.Attestations {
		assestation, err := validateAndBuildRemoteAttestation(remoteAttestationResponse,
			resp.Cookies,
			// KeyStore, -> Android secret iaskeystore
			keyPair,
			enclaveName,
		)
		if err != nil {
			log.Debugln(err)
		} else {
			assestations[fmt.Sprintf("%s", *publicKey)] = assestation

		}
	}

	return assestations, nil
}

func validateAndBuildRemoteAttestation(
	remoteAttestation *RemoteAttestationResponse,
	cookies []string,
	// keystore,
	keyPair *axolotl.ECKeyPair,
	enclaveName string,
) (*RemoteAttestation, error) {
	keys, err := remoteAttestationKeys(keyPair, remoteAttestation.ServerEphemeralPublic, remoteAttestation.ServerStaticPublic)
	if err != nil {
		return nil, err
	}
	requestId, err := getRequestId(keys, remoteAttestation)
	if err != nil {
		return nil, err
	}
	log.Debugln("[textsecure] requestId", requestId)
	// Quote                 quote     = new Quote(response.getQuote()); -> quote.go -> not necessary if we strip the verification

	// RemoteAttestationCipher.verifyServerQuote(quote, response.getServerStaticPublic(), mrenclave);

	// RemoteAttestationCipher.verifyIasSignature(iasKeyStore, response.getCertificates(), response.getSignatureBody(), response.getSignature(), quote);
	return &RemoteAttestation{
		Keys: *keys,
		// Quote:,
		RequestId: requestId,
	}, nil

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
func remoteAttestationKeys(keyPair *axolotl.ECKeyPair, serverPublicEphemarl []byte, serverPublicStatic []byte) (*RemoteAttestationKeys, error) {

	ephemeralToEphemeral := [32]byte{}
	serverPublicEphemarlPublicKey := axolotl.NewECPublicKey(serverPublicEphemarl).GetKey()
	axolotl.CalculateAgreement(&ephemeralToEphemeral, &serverPublicEphemarlPublicKey, keyPair.PrivateKey.Key())

	ephemeralToStatic := [32]byte{}
	serverPublicStaticPublicKey := axolotl.NewECPublicKey(serverPublicEphemarl).GetKey()
	axolotl.CalculateAgreement(&ephemeralToStatic, &serverPublicStaticPublicKey, keyPair.PrivateKey.Key())

	// public RemoteAttestationKeys(ECKeyPair keyPair, byte[] serverPublicEphemeral, byte[] serverPublicStatic) throws InvalidKeyException {
	//     byte[] ephemeralToEphemeral = Curve.calculateAgreement(ECPublicKey.fromPublicKeyBytes(serverPublicEphemeral), keyPair.getPrivateKey());
	//-> Curve.calculateAgreement is missing in our tool
	//     byte[] ephemeralToStatic    = Curve.calculateAgreement(ECPublicKey.fromPublicKeyBytes(serverPublicStatic), keyPair.getPrivateKey());
	//     byte[] masterSecret = ByteUtil.combine(ephemeralToEphemeral, ephemeralToStatic                          );
	masterSecret := append(ephemeralToEphemeral[:], ephemeralToStatic[:]...)
	//     byte[] publicKeys   = ByteUtil.combine(keyPair.getPublicKey().getPublicKeyBytes(), serverPublicEphemeral, serverPublicStatic);
	publicKeys := append(append(keyPair.PublicKey.Key()[:], serverPublicEphemarl...), serverPublicStatic...)
	log.Debugln(masterSecret, publicKeys)

	//     HKDFv3 generator = new HKDFv3();
	keys, err := axolotl.DeriveSecrets(masterSecret, publicKeys, nil, len(masterSecret)+len(publicKeys))
	if err != nil {
		return nil, err
	}
	clientKey := keys[:32]
	serverKey := keys[32:]
	// keys, err := textsecureCrypto.HKDFderiveSecrets(masterSecret, publicKeys, len()+len())
	//     byte[] keys      = generator.deriveSecrets(masterSecret, publicKeys, null, clientKey.length + serverKey.length);

	//     System.arraycopy(keys, 0, clientKey, 0, clientKey.length);
	//     System.arraycopy(keys, clientKey.length, serverKey, 0, serverKey.length);

	return &RemoteAttestationKeys{
		ClientKey: clientKey,
		ServerKey: serverKey,
	}, nil

}

func getRequestId(keys *RemoteAttestationKeys, response *RemoteAttestationResponse) ([]byte, error) {
	log.Debugln(keys.ServerKey)
	return textsecureCrypto.AesgcmDecrypt(keys.ServerKey, response.Iv, append(response.Ciphertext, response.Tag...))
}
