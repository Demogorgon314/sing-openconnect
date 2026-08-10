package openconnect

import (
	"bytes"
	"testing"
)

func FuzzCSTPPacketParser(f *testing.F) {
	f.Add([]byte{'S', 'T', 'F', 1, 0, 3, cstpPacketData, 0, 1, 2, 3})
	f.Add([]byte{'S', 'T', 'F', 1, 0, 1})
	f.Add([]byte{'B', 'A', 'D', 1, 0, 0, cstpPacketData, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > cstpMaximumPayloadSize+cstpHeaderSize {
			return
		}
		_, packet, err := readCSTPPacket(bytes.NewReader(data), cstpMaximumPayloadSize)
		if err != nil {
			return
		}
		defer packet.Release()
		if packet.Len() > cstpMaximumPayloadSize {
			t.Fatalf("parser returned an oversized CSTP payload: %d", packet.Len())
		}
	})
}

func FuzzAnyConnectAuthenticationXML(f *testing.F) {
	f.Add([]byte(`<config-auth><auth id="main"><form method="POST"><input name="username" type="text"/></form></auth></config-auth>`), "linux")
	f.Add([]byte(`<auth id="challenge"><message>Please enter a token</message></auth>`), "win")
	f.Add([]byte(`<config-auth><auth`), "mac-intel")
	f.Fuzz(func(t *testing.T, content []byte, reportedOS string) {
		if len(content) > 64*1024 || len(reportedOS) > 128 {
			return
		}
		_, _ = parseAnyConnectAuthenticationXML(content, reportedOS)
	})
}

func FuzzAnyConnectStatelessCompression(f *testing.F) {
	const maximumPayloadSize = 4096
	validPacket := make([]byte, 64)
	validPacket[0] = 0x45
	validPacket[2] = 0
	validPacket[3] = byte(len(validPacket))
	for _, compression := range []anyConnectCompression{anyConnectCompressionLZ4, anyConnectCompressionLZS} {
		compressed, ok := compressAnyConnectStatelessPacket(compression, validPacket)
		if ok {
			f.Add(uint8(compression), append([]byte(nil), compressed.Bytes()...))
			compressed.Release()
		}
	}
	f.Add(uint8(anyConnectCompressionLZ4), []byte{0xff})
	f.Add(uint8(anyConnectCompressionLZS), []byte{0xff})
	f.Fuzz(func(t *testing.T, compressionValue uint8, payload []byte) {
		if len(payload) > 64*1024 {
			return
		}
		compression := anyConnectCompressionLZ4
		if compressionValue&1 != 0 {
			compression = anyConnectCompressionLZS
		}
		packet, err := decompressAnyConnectStatelessPacket(compression, payload, maximumPayloadSize)
		if err != nil {
			return
		}
		defer packet.Release()
		if packet.Len() > maximumPayloadSize {
			t.Fatalf("decompressor returned an oversized packet: %d", packet.Len())
		}
	})
}

func FuzzLegacyDTLSRecordParser(f *testing.F) {
	cipher, err := anyConnectLegacyCipherForName("AES128-SHA", false)
	if err != nil {
		f.Fatal(err)
	}
	suite := cipher.suite()
	key := bytes.Repeat([]byte{0x11}, cipher.keyLength)
	macKey := bytes.Repeat([]byte{0x22}, legacyDTLSMACLength)
	validRecord, err := encryptLegacyDTLSRecord(legacyDTLSRecord{
		contentType: legacyDTLSContentApplication,
		epoch:       1,
		sequence:    1,
		payload:     []byte("packet"),
	}, key, macKey, suite)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validRecord)
	f.Add(validRecord[:legacyDTLSRecordHeaderLength-1])
	f.Add([]byte{legacyDTLSContentApplication, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, datagram []byte) {
		if len(datagram) > legacyDTLSReadBufferSize {
			return
		}
		mutable := append([]byte(nil), datagram...)
		records, parseErr := parseLegacyDTLSRecords(mutable, suite)
		if parseErr != nil || len(records) == 0 {
			return
		}
		_, _ = decryptLegacyDTLSRecord(records[0], key, macKey, suite)
	})
}
