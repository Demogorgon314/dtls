// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/protocol"
)

type blockingApplicationPacketConn struct {
	net.PacketConn
	batchRemoteAddress net.Addr
	access             sync.Mutex
	blocked            bool
	started            chan struct{}
	interrupted        chan struct{}
	startOnce          *sync.Once
	interruptOnce      *sync.Once
	deadlineErr        error
	alertWrites        atomic.Int64
}

func (c *blockingApplicationPacketConn) arm() <-chan struct{} {
	c.access.Lock()
	defer c.access.Unlock()
	c.blocked = true
	c.started = make(chan struct{})
	c.interrupted = make(chan struct{})
	c.startOnce = new(sync.Once)
	c.interruptOnce = new(sync.Once)
	return c.started
}

func (c *blockingApplicationPacketConn) failNextWriteDeadline(err error) {
	c.access.Lock()
	c.deadlineErr = err
	c.access.Unlock()
}

func (c *blockingApplicationPacketConn) WriteTo(packet []byte, remoteAddress net.Addr) (int, error) {
	if len(packet) > 0 && protocol.ContentType(packet[0]) == protocol.ContentTypeAlert {
		c.alertWrites.Add(1)
	}
	c.access.Lock()
	blocked := c.blocked && len(packet) > 0 && protocol.ContentType(packet[0]) == protocol.ContentTypeApplicationData
	started := c.started
	interrupted := c.interrupted
	startOnce := c.startOnce
	c.access.Unlock()
	if blocked {
		startOnce.Do(func() { close(started) })
		<-interrupted
		return 0, os.ErrDeadlineExceeded
	}
	return c.PacketConn.WriteTo(packet, remoteAddress)
}

func (c *blockingApplicationPacketConn) WritePacketBatchContext(ctx context.Context, packets [][]byte) error {
	for _, packet := range packets {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := c.WriteTo(packet, c.batchRemoteAddress); err != nil {
			return err
		}
	}
	return nil
}

func (c *blockingApplicationPacketConn) SetWriteDeadline(deadline time.Time) error {
	c.access.Lock()
	deadlineErr := c.deadlineErr
	c.deadlineErr = nil
	c.access.Unlock()
	if deadlineErr != nil {
		return deadlineErr
	}
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		c.access.Lock()
		if c.blocked {
			c.blocked = false
			c.interruptOnce.Do(func() { close(c.interrupted) })
		}
		c.access.Unlock()
	}
	return c.PacketConn.SetWriteDeadline(deadline)
}

func TestDedicatedPacketConnWriteLifecycle(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		batch bool
	}{
		{name: "single"},
		{name: "batch", batch: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			testDedicatedPacketConnWriteLifecycle(t, testCase.batch)
		})
	}
}

func testDedicatedPacketConnWriteLifecycle(t *testing.T, batch bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverPacketConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverPacketConn.Close()
	clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	clientPacketConn := &blockingApplicationPacketConn{
		PacketConn:         clientUDP,
		batchRemoteAddress: serverPacketConn.LocalAddr(),
	}
	defer clientPacketConn.Close()

	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	serverReady := make(chan struct {
		conn *Conn
		err  error
	}, 1)
	go func() {
		server, serverErr := testServer(ctx, serverPacketConn, clientPacketConn.LocalAddr(), &Config{
			Certificates: []tls.Certificate{certificate},
		}, false)
		serverReady <- struct {
			conn *Conn
			err  error
		}{server, serverErr}
	}()
	client, err := testClient(ctx, clientPacketConn, serverPacketConn.LocalAddr(), &Config{
		InsecureSkipVerify:  true,
		DedicatedPacketConn: true,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	serverResult := <-serverReady
	if serverResult.err != nil {
		t.Fatal(serverResult.err)
	}
	server := serverResult.conn
	defer server.Close()
	payloads := func(value string) [][]byte {
		result := [][]byte{[]byte(value)}
		if batch {
			result = append(result, []byte(value+"-second"))
		}
		return result
	}
	writePayloads := func(payloads [][]byte) error {
		if batch {
			return client.WritePackets(payloads)
		}
		for _, payload := range payloads {
			if _, writeErr := client.Write(payload); writeErr != nil {
				return writeErr
			}
		}
		return nil
	}
	readPayloads := func(payloads [][]byte) {
		t.Helper()
		for _, payload := range payloads {
			reply := make([]byte, len(payload))
			if _, readErr := server.Read(reply); readErr != nil {
				t.Fatal(readErr)
			}
			if string(reply) != string(payload) {
				t.Fatalf("payload changed: got %q, want %q", reply, payload)
			}
		}
	}
	initialDeadline := time.Now().Add(time.Minute)
	if err = client.SetWriteDeadline(initialDeadline); err != nil {
		t.Fatal(err)
	}
	deadlineErr := errors.New("write deadline rejected")
	clientPacketConn.failNextWriteDeadline(deadlineErr)
	if err = client.SetWriteDeadline(time.Now()); !errors.Is(err, deadlineErr) {
		t.Fatalf("failed write deadline returned %v", err)
	}
	testPayloads := payloads("after-failed-deadline")
	if err = writePayloads(testPayloads); err != nil {
		t.Fatalf("failed write deadline changed the previous deadline: %v", err)
	}
	readPayloads(testPayloads)

	started := clientPacketConn.arm()
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writePayloads(payloads("deadline"))
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err = client.SetWriteDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = <-writeDone; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked write returned %v instead of a deadline error", err)
	}
	if err = client.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	testPayloads = payloads("after-deadline")
	if err = writePayloads(testPayloads); err != nil {
		t.Fatal(err)
	}
	readPayloads(testPayloads)

	started = clientPacketConn.arm()
	go func() {
		writeDone <- writePayloads(payloads("close"))
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	if err = <-writeDone; !errors.Is(err, ErrConnClosed) {
		t.Fatalf("write interrupted by Close returned %v", err)
	}
	if err = <-closeDone; err != nil {
		t.Fatal(err)
	}
	if clientPacketConn.alertWrites.Load() == 0 {
		t.Fatal("Close did not send close_notify after interrupting the application write")
	}
}
