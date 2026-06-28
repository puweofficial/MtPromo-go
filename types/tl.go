// Package types contains TL (Type Language) serialization primitives
// used in the MTProto protocol.
package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
)

// TLBuffer is a helper for reading/writing TL-encoded data.
type TLBuffer struct {
	buf *bytes.Buffer
}

func NewTLBuffer() *TLBuffer {
	return &TLBuffer{buf: &bytes.Buffer{}}
}

func NewTLBufferFrom(data []byte) *TLBuffer {
	return &TLBuffer{buf: bytes.NewBuffer(data)}
}

func (b *TLBuffer) Bytes() []byte { return b.buf.Bytes() }

// WriteInt32 writes a 4-byte little-endian integer.
func (b *TLBuffer) WriteInt32(v int32) {
	_ = binary.Write(b.buf, binary.LittleEndian, v)
}

// WriteUInt32 writes an unsigned 4-byte little-endian integer.
func (b *TLBuffer) WriteUInt32(v uint32) {
	_ = binary.Write(b.buf, binary.LittleEndian, v)
}

// WriteInt64 writes an 8-byte little-endian integer.
func (b *TLBuffer) WriteInt64(v int64) {
	_ = binary.Write(b.buf, binary.LittleEndian, v)
}

// WriteBytes writes a TL byte string (with length prefix + padding).
func (b *TLBuffer) WriteBytes(data []byte) {
	l := len(data)
	if l < 254 {
		b.buf.WriteByte(byte(l))
		b.buf.Write(data)
		pad := (l + 1) % 4
		if pad > 0 {
			b.buf.Write(make([]byte, 4-pad))
		}
	} else {
		b.buf.WriteByte(254)
		b.buf.WriteByte(byte(l & 0xff))
		b.buf.WriteByte(byte((l >> 8) & 0xff))
		b.buf.WriteByte(byte((l >> 16) & 0xff))
		b.buf.Write(data)
		pad := l % 4
		if pad > 0 {
			b.buf.Write(make([]byte, 4-pad))
		}
	}
}

// WriteString writes a TL-encoded UTF-8 string.
func (b *TLBuffer) WriteString(s string) {
	b.WriteBytes([]byte(s))
}

// WriteBigInt writes a big integer in TL format.
func (b *TLBuffer) WriteBigInt(n *big.Int) {
	data := n.Bytes()
	// Pad to 256 bytes (for DH params)
	for len(data) < 256 {
		data = append([]byte{0}, data...)
	}
	b.WriteBytes(data)
}

// ReadInt32 reads a 4-byte little-endian integer.
func (b *TLBuffer) ReadInt32() (int32, error) {
	var v int32
	if err := binary.Read(b.buf, binary.LittleEndian, &v); err != nil {
		return 0, fmt.Errorf("ReadInt32: %w", err)
	}
	return v, nil
}

// ReadUInt32 reads an unsigned 4-byte little-endian integer.
func (b *TLBuffer) ReadUInt32() (uint32, error) {
	var v uint32
	if err := binary.Read(b.buf, binary.LittleEndian, &v); err != nil {
		return 0, fmt.Errorf("ReadUInt32: %w", err)
	}
	return v, nil
}

// ReadInt64 reads an 8-byte little-endian integer.
func (b *TLBuffer) ReadInt64() (int64, error) {
	var v int64
	if err := binary.Read(b.buf, binary.LittleEndian, &v); err != nil {
		return 0, fmt.Errorf("ReadInt64: %w", err)
	}
	return v, nil
}

// ReadBytes reads a TL byte string.
func (b *TLBuffer) ReadBytes() ([]byte, error) {
	firstByte, err := b.buf.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("ReadBytes first byte: %w", err)
	}
	var length int
	if firstByte < 254 {
		length = int(firstByte)
		data := make([]byte, length)
		if _, err := b.buf.Read(data); err != nil {
			return nil, err
		}
		pad := (length + 1) % 4
		if pad > 0 {
			b.buf.Next(4 - pad)
		}
		return data, nil
	}
	b1, _ := b.buf.ReadByte()
	b2, _ := b.buf.ReadByte()
	b3, _ := b.buf.ReadByte()
	length = int(b1) | int(b2)<<8 | int(b3)<<16
	data := make([]byte, length)
	if _, err := b.buf.Read(data); err != nil {
		return nil, err
	}
	pad := length % 4
	if pad > 0 {
		b.buf.Next(4 - pad)
	}
	return data, nil
}

// ReadString reads a TL-encoded string.
func (b *TLBuffer) ReadString() (string, error) {
	data, err := b.ReadBytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
}
