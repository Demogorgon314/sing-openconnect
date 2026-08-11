package openconnect

import (
	"bytes"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func TestAnyConnectInjectedAES256GCMApplicationRecord(t *testing.T) {
	const cipherName = "OC-DTLS1_2-AES256-GCM"
	_, _, senderSuite, err := anyConnectDTLS12CipherSuite(cipherName, true)
	if err != nil {
		t.Fatal(err)
	}
	_, _, receiverSuite, err := anyConnectDTLS12CipherSuite(cipherName, true)
	if err != nil {
		t.Fatal(err)
	}
	masterSecret := bytes.Repeat([]byte{0x42}, 48)
	clientRandom := bytes.Repeat([]byte{0x17}, 32)
	serverRandom := bytes.Repeat([]byte{0x29}, 32)
	if err = senderSuite.Init(masterSecret, clientRandom, serverRandom, true); err != nil {
		t.Fatal(err)
	}
	if err = receiverSuite.Init(masterSecret, clientRandom, serverRandom, false); err != nil {
		t.Fatal(err)
	}

	sender := senderSuite.(*anyConnectPionCipherSuite) //nolint:forcetypeassert // factory contract under test
	if _, fastPath := sender.protection.Load().(anyConnectPionApplicationDataCipher); !fastPath {
		t.Fatal("Cisco AES-256-GCM record protection does not expose the direct application-data path")
	}
	payload := []byte("injected-resumption application packet")
	header := recordlayer.Header{Version: protocol.Version1_2, Epoch: 1, SequenceNumber: 23}
	encrypted, err := sender.EncryptApplicationData(&header, payload)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := receiverSuite.Decrypt(recordlayer.Header{}, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	var decryptedHeader recordlayer.Header
	if err = decryptedHeader.Unmarshal(decrypted); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted[decryptedHeader.Size():], payload) {
		t.Fatal("Cisco AES-256-GCM direct record path changed the application payload")
	}
}
