// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/require"
)

func TestGCMEncryptApplicationData(t *testing.T) {
	localKey := sha256.Sum256([]byte("local-key"))
	remoteKey := sha256.Sum256([]byte("remote-key"))
	localIV := []byte{1, 2, 3, 4}
	remoteIV := []byte{5, 6, 7, 8}
	sender, err := NewGCM(localKey[:32], localIV, remoteKey[:32], remoteIV)
	require.NoError(t, err)
	receiver, err := NewGCM(remoteKey[:32], remoteIV, localKey[:32], localIV)
	require.NoError(t, err)

	payload := []byte("anyconnect application packet")
	original := append([]byte(nil), payload...)
	header := recordlayer.Header{Version: protocol.Version1_2, Epoch: 3, SequenceNumber: 17}
	encrypted, err := sender.EncryptApplicationData(&header, payload)
	require.NoError(t, err)
	require.Equal(t, original, payload)
	require.Equal(t, uint16(8+len(payload)+gcmTagLength), header.ContentLen) //nolint:gosec // bounded test payload

	decrypted, err := receiver.Decrypt(recordlayer.Header{}, encrypted)
	require.NoError(t, err)
	var decryptedHeader recordlayer.Header
	require.NoError(t, decryptedHeader.Unmarshal(decrypted))
	require.Equal(t, header.ContentType, decryptedHeader.ContentType)
	require.Equal(t, header.Version, decryptedHeader.Version)
	require.Equal(t, header.Epoch, decryptedHeader.Epoch)
	require.Equal(t, header.SequenceNumber, decryptedHeader.SequenceNumber)
	require.Equal(t, header.ContentLen, binary.BigEndian.Uint16(encrypted[header.Size()-2:]))
	require.Equal(t, payload, decrypted[decryptedHeader.Size():])

	maximumPayload := make([]byte, math.MaxUint16-8-gcmTagLength)
	_, err = sender.EncryptApplicationData(&header, maximumPayload)
	require.NoError(t, err)
	_, err = sender.EncryptApplicationData(&header, append(maximumPayload, 0))
	require.ErrorIs(t, err, errApplicationDataTooLarge)
}

func FuzzGCM_RoundTrip(f *testing.F) {
	f.Add([]byte{}, []byte("x"), uint64(0), uint16(0))
	f.Add([]byte{7, 8, 9}, []byte("alpha"), uint64(5), uint16(1))
	f.Add(make([]byte, 2048), []byte("left"), uint64(0x0a0b0c0d0e0f), uint16(3))

	f.Fuzz(func(t *testing.T, plain []byte, seed []byte, seq uint64, epoch uint16) {
		if len(plain) > 1<<14 {
			plain = plain[:1<<14]
		}

		h := sha256.Sum256(seed)
		localKey := h[:16]
		localWriteIV := h[16:20]

		gcmAEAD, err := NewGCM(localKey, localWriteIV, localKey, localWriteIV)
		require.NoError(t, err)

		hdr := recordlayer.Header{
			ContentType:    protocol.ContentTypeApplicationData,
			Version:        protocol.Version1_2,
			Epoch:          epoch,
			SequenceNumber: seq,
		}

		headerRaw, err := hdr.Marshal()
		require.NoError(t, err)

		raw := make([]byte, len(headerRaw)+len(plain))
		copy(raw, headerRaw)
		copy(raw[len(headerRaw):], plain)

		enc, err := gcmAEAD.Encrypt(&recordlayer.RecordLayer{Header: hdr}, raw)
		require.NoError(t, err)

		dec, err := gcmAEAD.Decrypt(recordlayer.Header{}, enc)
		require.NoError(t, err)

		var parsedHdr recordlayer.Header
		require.NoError(t, parsedHdr.Unmarshal(dec))
		got := dec[parsedHdr.Size():]

		require.Equal(t, plain, got)
	})
}

func FuzzGCM_Bidirectional_RoundTrip(f *testing.F) {
	f.Add([]byte("hello"), []byte("seedA"), uint64(1), uint16(0),
		[]byte("world"), []byte("seedB"), uint64(2), uint16(1))

	f.Add([]byte{}, []byte("zero"), uint64(0), uint16(0),
		[]byte{1, 2, 3, 4}, []byte("other"), uint64(5), uint16(2))

	f.Add(make([]byte, 2048), []byte("AAA"), uint64(123456), uint16(3),
		make([]byte, 17), []byte("BBB"), uint64(789), uint16(4))

	f.Fuzz(func(t *testing.T,
		pA []byte, sA []byte, seqA uint64, epochA uint16,
		pB []byte, sB []byte, seqB uint64, epochB uint16,
	) {
		if len(pA) > 1<<14 {
			pA = pA[:1<<14]
		}

		if len(pB) > 1<<14 {
			pB = pB[:1<<14]
		}

		hA := sha256.Sum256(sA)
		hB := sha256.Sum256(sB)
		localKeyA, localWriteIVA := hA[:16], hA[16:20]
		localKeyB, localWriteIVB := hB[:16], hB[16:20]

		// A uses (keyA,ivA) to send and expects (keyB, ivB) for receive.
		gcmA, err := NewGCM(localKeyA, localWriteIVA, localKeyB, localWriteIVB)
		require.NoError(t, err)

		// B uses (keyB,ivB) to send and expects (keyA, ivA) for receive.
		gcmB, err := NewGCM(localKeyB, localWriteIVB, localKeyA, localWriteIVA)
		require.NoError(t, err)

		// A -> B
		hdrA := recordlayer.Header{
			ContentType:    protocol.ContentTypeApplicationData,
			Version:        protocol.Version1_2,
			Epoch:          epochA,
			SequenceNumber: seqA,
		}

		headerRawA, err := hdrA.Marshal()
		require.NoError(t, err)

		rawA := make([]byte, len(headerRawA)+len(pA))
		copy(rawA, headerRawA)
		copy(rawA[len(headerRawA):], pA)

		encA, err := gcmA.Encrypt(&recordlayer.RecordLayer{Header: hdrA}, rawA)
		require.NoError(t, err)

		decAonB, err := gcmB.Decrypt(recordlayer.Header{}, encA)
		require.NoError(t, err)

		// parse header from decrypted bytes to compute payload offset safely.
		var parsedHdrA recordlayer.Header
		require.NoError(t, parsedHdrA.Unmarshal(decAonB))

		gotA := decAonB[parsedHdrA.Size():]
		require.Equal(t, pA, gotA)

		// B -> A
		hdrB := recordlayer.Header{
			ContentType:    protocol.ContentTypeApplicationData,
			Version:        protocol.Version1_2,
			Epoch:          epochB,
			SequenceNumber: seqB,
		}

		headerRawB, err := hdrB.Marshal()
		require.NoError(t, err)

		rawB := make([]byte, len(headerRawB)+len(pB))
		copy(rawB, headerRawB)
		copy(rawB[len(headerRawB):], pB)

		encB, err := gcmB.Encrypt(&recordlayer.RecordLayer{Header: hdrB}, rawB)
		require.NoError(t, err)

		decBonA, err := gcmA.Decrypt(recordlayer.Header{}, encB)
		require.NoError(t, err)

		var parsedHdrB recordlayer.Header
		require.NoError(t, parsedHdrB.Unmarshal(decBonA))

		gotB := decBonA[parsedHdrB.Size():]
		require.Equal(t, pB, gotB)
	})
}
