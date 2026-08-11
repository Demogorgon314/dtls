// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v4/dpipe"
	"github.com/stretchr/testify/require"
)

type recordingPacketBatchConn struct {
	net.PacketConn
	batchWrites atomic.Int32
}

func (c *recordingPacketBatchConn) WritePacketBatchContext(ctx context.Context, packets [][]byte) error {
	c.batchWrites.Add(1)
	for _, packet := range packets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if _, err := c.WriteTo(packet, nil); err != nil {
			return err
		}
	}
	return nil
}

func TestWritePacketsUsesPacketBatchWriter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientTransport, serverTransport := dpipe.Pipe()
	clientPacketConn := &recordingPacketBatchConn{PacketConn: dtlsnet.PacketConnFromConn(clientTransport)}
	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	serverReady := make(chan *Conn, 1)
	serverErr := make(chan error, 1)
	go func() {
		server, serveErr := testServer(ctx, dtlsnet.PacketConnFromConn(serverTransport), serverTransport.RemoteAddr(), &Config{
			Certificates: []tls.Certificate{certificate},
		}, false)
		if serveErr != nil {
			serverErr <- serveErr
			return
		}
		serverReady <- server
	}()

	client, err := testClient(ctx, clientPacketConn, clientTransport.RemoteAddr(), &Config{InsecureSkipVerify: true}, false)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, client.Close())
	}()

	var server *Conn
	select {
	case server = <-serverReady:
	case err = <-serverErr:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer func() {
		require.NoError(t, server.Close())
	}()

	clientPacketConn.batchWrites.Store(0)
	payloads := [][]byte{
		bytes.Repeat([]byte{1}, 1400),
		bytes.Repeat([]byte{2}, 1400),
		bytes.Repeat([]byte{3}, 1400),
	}
	require.NoError(t, client.WritePackets(payloads))
	require.Equal(t, int32(1), clientPacketConn.batchWrites.Load())

	readBuffer := make([]byte, 1600)
	for _, payload := range payloads {
		n, readErr := server.Read(readBuffer)
		require.NoError(t, readErr)
		require.Equal(t, payload, readBuffer[:n])
	}
}
