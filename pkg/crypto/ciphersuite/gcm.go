// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"math"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

const (
	gcmTagLength   = 16
	gcmNonceLength = 12
)

// GCM Provides an API to Encrypt/Decrypt DTLS 1.2 Packets.
type GCM struct {
	aead *aead
}

// NewGCM creates a DTLS GCM Cipher.
func NewGCM(localKey, localWriteIV, remoteKey, remoteWriteIV []byte) (*GCM, error) {
	localBlock, err := aes.NewCipher(localKey)
	if err != nil {
		return nil, err
	}
	localGCM, err := cipher.NewGCM(localBlock)
	if err != nil {
		return nil, err
	}

	remoteBlock, err := aes.NewCipher(remoteKey)
	if err != nil {
		return nil, err
	}
	remoteGCM, err := cipher.NewGCM(remoteBlock)
	if err != nil {
		return nil, err
	}

	return &GCM{
		aead: newAEAD(
			localGCM,
			localWriteIV,
			remoteGCM,
			remoteWriteIV,
			gcmNonceLength,
			gcmTagLength,
		),
	}, nil
}

// Encrypt encrypts a DTLS RecordLayer message.
func (g *GCM) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	return g.aead.encrypt(pkt, raw)
}

// EncryptApplicationData encrypts application data directly into its final
// DTLS 1.2 wire record without constructing an intermediate plaintext record.
func (g *GCM) EncryptApplicationData(header *recordlayer.Header, payload []byte) ([]byte, error) {
	const recordOverhead = 8 + gcmTagLength
	if len(payload) > math.MaxUint16-recordOverhead {
		return nil, errApplicationDataTooLarge
	}

	header.ContentType = protocol.ContentTypeApplicationData
	header.ContentLen = uint16(len(payload) + recordOverhead) //nolint:gosec // bounded above
	headerSize := header.Size()
	result := make([]byte, headerSize+8, headerSize+recordOverhead+len(payload))
	if err := header.MarshalInto(result); err != nil {
		return nil, err
	}

	noncePtr := g.aead.nonceBufferPool.Get().(*[]byte) //nolint:forcetypeassert
	nonce := *noncePtr
	defer g.aead.nonceBufferPool.Put(noncePtr)
	copy(nonce, g.aead.localWriteIV[:4])
	seq64 := (uint64(header.Epoch) << 48) | (header.SequenceNumber & 0x0000ffffffffffff)
	binary.BigEndian.PutUint64(nonce[4:], seq64)

	copy(result[headerSize:], nonce[4:])
	additionalData := generateAEADAdditionalData(header, len(payload))

	return g.aead.localAEAD.Seal(result, nonce, payload, additionalData), nil
}

// Decrypt decrypts a DTLS RecordLayer message.
func (g *GCM) Decrypt(header recordlayer.Header, in []byte) ([]byte, error) {
	return g.aead.decrypt(header, in)
}
