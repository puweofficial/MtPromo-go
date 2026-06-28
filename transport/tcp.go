// Package transport provides TCP connectivity to Telegram's MTProto servers.
// It implements the "abridged" transport codec — the simplest framing used by
// modern Telegram clients.
package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	abridgedMagic = 0xef // First byte that signals abridged mode
	dialTimeout   = 15 * time.Second
	rwTimeout     = 30 * time.Second
)

// Conn wraps a raw TCP connection and handles MTProto abridged framing.
type Conn struct {
	conn net.Conn
}

// Dial opens a TCP connection to addr and performs the abridged handshake.
func Dial(addr string) (*Conn, error) {
	raw, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("transport: dial %s: %w", addr, err)
	}
	c := &Conn{conn: raw}
	// Send the abridged init byte
	if _, err := raw.Write([]byte{abridgedMagic}); err != nil {
		raw.Close()
		return nil, fmt.Errorf("transport: abridged handshake: %w", err)
	}
	return c, nil
}

// Send sends a payload using abridged framing.
// Length is encoded as 1 byte (payload/4) if < 127, or 4 bytes otherwise.
func (c *Conn) Send(data []byte) error {
	if len(data)%4 != 0 {
		return errors.New("transport: payload length must be multiple of 4")
	}
	c.conn.SetWriteDeadline(time.Now().Add(rwTimeout)) //nolint:errcheck
	words := len(data) / 4

	var header []byte
	if words < 127 {
		header = []byte{byte(words)}
	} else {
		header = make([]byte, 4)
		binary.LittleEndian.PutUint32(header, uint32(words<<8)|0x7f)
	}

	if _, err := c.conn.Write(append(header, data...)); err != nil {
		return fmt.Errorf("transport: send: %w", err)
	}
	return nil
}

// Recv reads the next frame from the connection.
func (c *Conn) Recv() ([]byte, error) {
	c.conn.SetReadDeadline(time.Now().Add(rwTimeout)) //nolint:errcheck

	first := make([]byte, 1)
	if _, err := io.ReadFull(c.conn, first); err != nil {
		return nil, fmt.Errorf("transport: recv header: %w", err)
	}

	var length int
	if first[0] < 0x7f {
		length = int(first[0]) * 4
	} else {
		// Read 3 more bytes
		rest := make([]byte, 3)
		if _, err := io.ReadFull(c.conn, rest); err != nil {
			return nil, fmt.Errorf("transport: recv extended header: %w", err)
		}
		length = (int(rest[0]) | int(rest[1])<<8 | int(rest[2])<<16) * 4
	}

	if length == 0 || length > 16*1024*1024 {
		return nil, fmt.Errorf("transport: invalid frame length %d", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return nil, fmt.Errorf("transport: recv body: %w", err)
	}
	return data, nil
}

// Close closes the underlying connection.
func (c *Conn) Close() error { return c.conn.Close() }

// RemoteAddr returns the remote address of the connection.
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
