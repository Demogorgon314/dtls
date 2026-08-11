// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"sync"
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
	batchWrites  atomic.Int32
	batchPackets atomic.Int32
}

type recordingPacketBatchReadConn struct {
	net.PacketConn
	enabled       atomic.Bool
	batchReads    atomic.Int32
	batchPackets  atomic.Int32
	releases      atomic.Int32
	batchReleased chan struct{}
}

func (c *recordingPacketBatchReadConn) ReadPacketBatchContext(ctx context.Context) ([][]byte, net.Addr, func(), error) {
	readPacket := func() ([]byte, net.Addr, error) {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}
		packet := make([]byte, inboundBufferSize)
		count, address, err := c.ReadFrom(packet)
		if err != nil {
			return nil, nil, err
		}
		return packet[:count], address, nil
	}

	packet, address, err := readPacket()
	if err != nil {
		return nil, nil, nil, err
	}
	packets := [][]byte{packet}
	batched := c.enabled.Load()
	if batched {
		for len(packets) < 3 {
			packet, _, readErr := readPacket()
			if readErr != nil {
				return nil, nil, nil, readErr
			}
			packets = append(packets, packet)
		}
		c.batchReads.Add(1)
		c.batchPackets.Add(int32(len(packets)))
	}
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			for _, packet := range packets {
				clear(packet)
			}
			if batched {
				c.releases.Add(1)
				close(c.batchReleased)
			}
		})
	}
	return packets, address, release, nil
}

func (c *recordingPacketBatchConn) WritePacketBatchContext(ctx context.Context, packets [][]byte) error {
	c.batchWrites.Add(1)
	c.batchPackets.Add(int32(len(packets)))
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
	clientPacketConn.batchPackets.Store(0)
	payloads := [][]byte{
		bytes.Repeat([]byte{1}, 64),
		bytes.Repeat([]byte{2}, 64),
		bytes.Repeat([]byte{3}, 64),
	}
	require.NoError(t, client.WritePackets(payloads))
	require.Equal(t, int32(1), clientPacketConn.batchWrites.Load())
	require.Equal(t, int32(len(payloads)), clientPacketConn.batchPackets.Load())

	readBuffer := make([]byte, 1600)
	for _, payload := range payloads {
		n, readErr := server.Read(readBuffer)
		require.NoError(t, readErr)
		require.Equal(t, payload, readBuffer[:n])
	}
}

func TestReadUsesPacketBatchReader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientTransport, serverTransport := dpipe.Pipe()
	serverPacketConn := &recordingPacketBatchReadConn{
		PacketConn:    dtlsnet.PacketConnFromConn(serverTransport),
		batchReleased: make(chan struct{}),
	}
	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	serverReady := make(chan *Conn, 1)
	serverErr := make(chan error, 1)
	go func() {
		server, serveErr := testServer(ctx, serverPacketConn, serverTransport.RemoteAddr(), &Config{
			Certificates: []tls.Certificate{certificate},
		}, false)
		if serveErr != nil {
			serverErr <- serveErr
			return
		}
		serverReady <- server
	}()

	client, err := testClient(ctx, dtlsnet.PacketConnFromConn(clientTransport), clientTransport.RemoteAddr(), &Config{InsecureSkipVerify: true}, false)
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

	serverPacketConn.enabled.Store(true)
	payloads := [][]byte{
		bytes.Repeat([]byte{1}, 64),
		bytes.Repeat([]byte{2}, 64),
		bytes.Repeat([]byte{3}, 64),
	}
	require.NoError(t, client.WritePackets(payloads))

	select {
	case <-serverPacketConn.batchReleased:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	received, readErr := server.ReadPackets()
	require.NoError(t, readErr)
	require.Equal(t, payloads, received)
	require.Equal(t, int32(1), serverPacketConn.batchReads.Load())
	require.Equal(t, int32(len(payloads)), serverPacketConn.batchPackets.Load())
	require.Equal(t, int32(1), serverPacketConn.releases.Load())

	require.NoError(t, server.SetReadDeadline(time.Now()))
	received, readErr = server.ReadPackets()
	require.Nil(t, received)
	require.ErrorIs(t, readErr, errDeadlineExceeded)
	require.NoError(t, server.SetReadDeadline(time.Time{}))
}
