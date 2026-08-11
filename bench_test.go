// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/logging"
	"github.com/pion/transport/v4/dpipe"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
)

func TestSimpleReadWrite(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, cb := dpipe.Pipe()
	certificate, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	gotHello := make(chan struct{})

	go func() {
		server, sErr := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
			Certificates:  []tls.Certificate{certificate},
			LoggerFactory: logging.NewDefaultLoggerFactory(),
		}, false)
		assert.NoError(t, sErr)

		buf := make([]byte, 1024)
		_, sErr = server.Read(buf) //nolint:contextcheck
		assert.NoError(t, sErr)

		gotHello <- struct{}{}
		assert.NoError(t, server.Close()) //nolint:contextcheck
	}()

	client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
		LoggerFactory:      logging.NewDefaultLoggerFactory(),
		InsecureSkipVerify: true,
	}, false)
	assert.NoError(t, err)
	_, err = client.Write([]byte("hello"))
	assert.NoError(t, err)
	select {
	case <-gotHello:
		// OK
	case <-time.After(time.Second * 5):
		assert.Fail(t, "timeout")
	}
	assert.NoError(t, client.Close())
}

func benchmarkConn(b *testing.B, payloadSize int64) {
	b.Helper()

	b.Run(fmt.Sprintf("%d", payloadSize), func(b *testing.B) {
		ctx := context.Background()

		ca, cb := dpipe.Pipe()
		certificate, err := selfsign.GenerateSelfSigned()
		assert.NoError(b, err)
		server := make(chan *Conn)

		go func() {
			s, sErr := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
				Certificates: []tls.Certificate{certificate},
			}, false)
			assert.NoError(b, sErr)

			server <- s
		}()

		hw := make([]byte, payloadSize)
		b.ReportAllocs()
		b.SetBytes(int64(len(hw)))
		go func() {
			client, cErr := testClient(
				ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{InsecureSkipVerify: true}, false,
			)
			assert.NoError(b, cErr)
			for {
				_, cErr = client.Write(hw) //nolint:contextcheck
				assert.NoError(b, cErr)
			}
		}()
		s := <-server
		buf := make([]byte, 2048)
		for i := 0; i < b.N; i++ {
			_, err = s.Read(buf)
			assert.NoError(b, err)
		}
	})
}

func BenchmarkConnReadWrite(b *testing.B) {
	for _, n := range []int64{16, 128, 512, 1024, 2048} {
		benchmarkConn(b, n)
	}
}

// BenchmarkAnyConnectP2DTLSUDP measures the Pion record encryption and
// connected-UDP write path used by AnyConnect. Every record carries a sequence
// and payload canary that the peer validates before the iteration completes.
func BenchmarkAnyConnectP2DTLSUDP(b *testing.B) {
	for _, cipherSuite := range []struct {
		name string
		id   CipherSuiteID
		psk  bool
	}{
		{name: "AES128-GCM", id: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		{name: "PSK-ChaCha20-Poly1305", id: TLS_PSK_WITH_CHACHA20_POLY1305_SHA256, psk: true},
	} {
		b.Run(cipherSuite.name, func(b *testing.B) {
			benchmarkAnyConnectP2DTLSUDP(b, cipherSuite.id, cipherSuite.psk)
		})
	}
}

// BenchmarkAnyConnectRecordProtection isolates the steady-state DTLS 1.2
// application-record construction and encryption path. It excludes handshake,
// queues, socket I/O, and peer scheduling so allocation and cipher changes can
// be screened locally before running the full UDP and Docker benchmarks.
func BenchmarkAnyConnectRecordProtection(b *testing.B) {
	for _, cipherSuite := range []struct {
		name string
		id   CipherSuiteID
	}{
		{name: "AES256-GCM", id: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		{name: "PSK-ChaCha20-Poly1305", id: TLS_PSK_WITH_CHACHA20_POLY1305_SHA256},
	} {
		b.Run(cipherSuite.name, func(b *testing.B) {
			benchmarkAnyConnectRecordProtection(b, cipherSuite.id)
		})
	}
}

func benchmarkAnyConnectRecordProtection(b *testing.B, cipherSuiteID CipherSuiteID) {
	b.Helper()

	for _, payloadSize := range []int{128, 512, 1200, 1400} {
		b.Run(fmt.Sprintf("%dB", payloadSize), func(b *testing.B) {
			masterSecret := make([]byte, 48)
			clientRandom := make([]byte, 32)
			serverRandom := make([]byte, 32)
			for index := range masterSecret {
				masterSecret[index] = byte(index*17 + 3)
			}
			for index := range clientRandom {
				clientRandom[index] = byte(index*29 + 5)
				serverRandom[index] = byte(index*31 + 7)
			}

			localCipher := cipherSuiteForID(cipherSuiteID, nil)
			if localCipher == nil {
				b.Fatalf("unsupported cipher suite %s", cipherSuiteID)
			}
			if err := localCipher.Init(masterSecret, clientRandom, serverRandom, true); err != nil {
				b.Fatal(err)
			}
			remoteCipher := cipherSuiteForID(cipherSuiteID, nil)
			if err := remoteCipher.Init(masterSecret, clientRandom, serverRandom, false); err != nil {
				b.Fatal(err)
			}

			client := &Conn{state: State{cipherSuite: localCipher}}
			client.state.localEpoch.Store(uint16(1))
			client.state.localSequenceNumber = []uint64{0, 0}
			packetPayload := newDTLSBenchmarkPacket(payloadSize)
			packet := &packet{
				record: &recordlayer.RecordLayer{
					Header:  recordlayer.Header{Epoch: 1, Version: protocol.Version1_2},
					Content: &protocol.ApplicationData{Data: packetPayload},
				},
				shouldEncrypt: true,
			}

			var raw []byte
			var err error
			b.ReportAllocs()
			b.SetBytes(int64(payloadSize))
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				setDTLSBenchmarkPacketSequence(packetPayload, uint64(iteration))
				raw, err = client.processPacket(packet)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()

			decrypted, err := remoteCipher.Decrypt(recordlayer.Header{}, raw)
			if err != nil {
				b.Fatalf("decrypt final benchmark record: %v", err)
			}
			var header recordlayer.Header
			if err = header.Unmarshal(decrypted); err != nil {
				b.Fatalf("parse final benchmark record: %v", err)
			}
			if header.SequenceNumber != uint64(b.N-1) {
				b.Fatalf("final record sequence = %d, want %d", header.SequenceNumber, b.N-1)
			}
			if err = validateDTLSBenchmarkPacket(decrypted[header.Size():], uint64(b.N-1)); err != nil {
				b.Fatal(err)
			}
		})
	}
}

func benchmarkAnyConnectP2DTLSUDP(b *testing.B, cipherSuite CipherSuiteID, usePSK bool) {
	b.Helper()

	for _, payloadSize := range []int{128, 512, 1200, 1400} {
		b.Run(fmt.Sprintf("%dB", payloadSize), func(b *testing.B) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			serverPacketConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				b.Fatal(err)
			}
			defer serverPacketConn.Close()
			clientPacketConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				b.Fatal(err)
			}
			defer clientPacketConn.Close()

			serverConfig := &Config{CipherSuites: []CipherSuiteID{cipherSuite}}
			clientConfig := &Config{
				InsecureSkipVerify:  true,
				CipherSuites:        []CipherSuiteID{cipherSuite},
				DedicatedPacketConn: true,
			}
			if usePSK {
				psk := []byte("anyconnect-benchmark-psk")
				pskCallback := func([]byte) ([]byte, error) { return psk, nil }
				serverConfig.PSK = pskCallback
				clientConfig.PSK = pskCallback
				clientConfig.PSKIdentityHint = []byte("anyconnect-benchmark")
			} else {
				certificate, generateErr := selfsign.GenerateSelfSigned()
				if generateErr != nil {
					b.Fatal(generateErr)
				}
				serverConfig.Certificates = []tls.Certificate{certificate}
			}
			type serverResult struct {
				conn *Conn
				err  error
			}
			serverReady := make(chan serverResult, 1)
			go func() {
				server, serverErr := testServer(ctx, serverPacketConn, clientPacketConn.LocalAddr(), serverConfig, false)
				serverReady <- serverResult{conn: server, err: serverErr}
			}()
			client, err := testClient(ctx, clientPacketConn, serverPacketConn.LocalAddr(), clientConfig, false)
			if err != nil {
				b.Fatal(err)
			}
			defer client.Close()
			result := <-serverReady
			if result.err != nil {
				b.Fatal(result.err)
			}
			server := result.conn
			defer server.Close()
			if state, ok := client.ConnectionState(); !ok || state.CipherSuiteID != cipherSuite {
				b.Fatalf("unexpected DTLS benchmark cipher suite: state=%#v available=%v", state, ok)
			}

			packet := newDTLSBenchmarkPacket(payloadSize)
			writeDone := make(chan error, 1)
			windowRead := make(chan struct{})
			const maximumInFlightPackets = 64
			b.ReportAllocs()
			b.SetBytes(int64(payloadSize))
			b.ResetTimer()
			go func() {
				for base := 0; base < b.N; base += maximumInFlightPackets {
					count := min(maximumInFlightPackets, b.N-base)
					for offset := range count {
						sequence := base + offset
						setDTLSBenchmarkPacketSequence(packet, uint64(sequence))
						if _, writeErr := client.Write(packet); writeErr != nil {
							writeDone <- fmt.Errorf("write record %d: %w", sequence, writeErr)
							return
						}
					}
					<-windowRead
				}
				writeDone <- nil
			}()

			readBuffer := make([]byte, payloadSize+64)
			for expected := 0; expected < b.N; expected++ {
				count, readErr := server.Read(readBuffer)
				if readErr != nil {
					cancel()
					b.Fatalf("read record %d: %v", expected, readErr)
				}
				if err = validateDTLSBenchmarkPacket(readBuffer[:count], uint64(expected)); err != nil {
					cancel()
					b.Fatal(err)
				}
				if (expected+1)%maximumInFlightPackets == 0 || expected+1 == b.N {
					windowRead <- struct{}{}
				}
			}
			if err = <-writeDone; err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
		})
	}
}

const dtlsBenchmarkPacketMagic = 0x41434e42

func newDTLSBenchmarkPacket(size int) []byte {
	if size < 24 {
		panic("DTLS benchmark packet must be at least 24 bytes")
	}
	packet := make([]byte, size)
	binary.BigEndian.PutUint32(packet[0:4], dtlsBenchmarkPacketMagic)
	binary.BigEndian.PutUint32(packet[4:8], uint32(size))
	for index := 24; index < len(packet); index++ {
		packet[index] = byte(index*31 + 17)
	}
	return packet
}

func setDTLSBenchmarkPacketSequence(packet []byte, sequence uint64) {
	binary.BigEndian.PutUint64(packet[8:16], sequence)
	binary.BigEndian.PutUint64(packet[16:24], ^sequence)
}

func validateDTLSBenchmarkPacket(packet []byte, expectedSequence uint64) error {
	if len(packet) < 24 || binary.BigEndian.Uint32(packet[0:4]) != dtlsBenchmarkPacketMagic {
		return fmt.Errorf("invalid DTLS benchmark packet header at sequence %d", expectedSequence)
	}
	if int(binary.BigEndian.Uint32(packet[4:8])) != len(packet) {
		return fmt.Errorf("DTLS benchmark packet length mismatch at sequence %d", expectedSequence)
	}
	sequence := binary.BigEndian.Uint64(packet[8:16])
	if sequence != expectedSequence || binary.BigEndian.Uint64(packet[16:24]) != ^sequence {
		return fmt.Errorf("DTLS benchmark sequence mismatch: got %d, want %d", sequence, expectedSequence)
	}
	for index := 24; index < len(packet); index++ {
		if packet[index] != byte(index*31+17) {
			return fmt.Errorf("DTLS benchmark payload changed at sequence %d offset %d", sequence, index)
		}
	}
	return nil
}
