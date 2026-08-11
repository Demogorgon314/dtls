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

			certificate, err := selfsign.GenerateSelfSigned()
			if err != nil {
				b.Fatal(err)
			}
			type serverResult struct {
				conn *Conn
				err  error
			}
			serverReady := make(chan serverResult, 1)
			go func() {
				server, serverErr := testServer(ctx, serverPacketConn, clientPacketConn.LocalAddr(), &Config{
					Certificates: []tls.Certificate{certificate},
					CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				}, false)
				serverReady <- serverResult{conn: server, err: serverErr}
			}()
			client, err := testClient(ctx, clientPacketConn, serverPacketConn.LocalAddr(), &Config{
				InsecureSkipVerify:  true,
				CipherSuites:        []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				DedicatedPacketConn: true,
			}, false)
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
			if state, ok := client.ConnectionState(); !ok || state.CipherSuiteID != TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 {
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
