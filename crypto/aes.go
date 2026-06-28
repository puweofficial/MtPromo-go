// Package crypto implements cryptographic primitives required by MTProto.
// Notably: AES-256-IGE mode, SHA1/SHA256, and key derivation.
package crypto

import (
	"crypto/aes"
	"crypto/sha1" //nolint:gosec // MTProto requires SHA1
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

// AesIgeEncrypt encrypts data using AES-256-IGE mode.
func AesIgeEncrypt(data, key, iv []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, errors.New("aes-ige: data length must be multiple of 16")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(data))
	iv1 := make([]byte, 16)
	iv2 := make([]byte, 16)
	copy(iv1, iv[:16])
	copy(iv2, iv[16:])

	for i := 0; i < len(data); i += 16 {
		chunk := data[i : i+16]
		// XOR chunk with iv1
		xored := xorBytes(chunk, iv1)
		// Encrypt
		block.Encrypt(encrypted[i:i+16], xored)
		// XOR result with iv2
		for j := 0; j < 16; j++ {
			encrypted[i+j] ^= iv2[j]
		}
		// Update ivs
		copy(iv1, encrypted[i:i+16])
		copy(iv2, chunk)
	}
	return encrypted, nil
}

// AesIgeDecrypt decrypts data using AES-256-IGE mode.
func AesIgeDecrypt(data, key, iv []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, errors.New("aes-ige: data length must be multiple of 16")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(data))
	iv1 := make([]byte, 16)
	iv2 := make([]byte, 16)
	copy(iv1, iv[:16])
	copy(iv2, iv[16:])

	for i := 0; i < len(data); i += 16 {
		chunk := data[i : i+16]
		// XOR chunk with iv2
		xored := xorBytes(chunk, iv2)
		// Decrypt
		block.Decrypt(decrypted[i:i+16], xored)
		// XOR result with iv1
		for j := 0; j < 16; j++ {
			decrypted[i+j] ^= iv1[j]
		}
		// Update ivs
		copy(iv2, chunk)
		copy(iv1, decrypted[i:i+16])
	}
	return decrypted, nil
}

// SHA1 returns SHA-1 digest.
func SHA1(data ...[]byte) []byte {
	h := sha1.New() //nolint:gosec
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// SHA256 returns SHA-256 digest.
func SHA256(data ...[]byte) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// MessageKey computes the 128-bit message key from the plaintext payload.
// In MTProto v2, msg_key = middle 128 bits of SHA-256(authKeyPart + plaintext).
func MessageKey(authKey, plaintext []byte, outgoing bool) []byte {
	x := 0
	if !outgoing {
		x = 8
	}
	return SHA256(authKey[88+x:88+x+32], plaintext)[8:24]
}

// DeriveKeys derives aes_key and aes_iv from auth_key and msg_key (MTProto v2).
func DeriveKeys(authKey, msgKey []byte, outgoing bool) (aesKey, aesIV []byte) {
	x := 0
	if !outgoing {
		x = 8
	}
	sha256a := SHA256(msgKey, authKey[x:x+36])
	sha256b := SHA256(authKey[40+x:40+x+36], msgKey)

	aesKey = make([]byte, 32)
	aesIV = make([]byte, 32)

	copy(aesKey[:8], sha256a[:8])
	copy(aesKey[8:24], sha256b[8:24])
	copy(aesKey[24:], sha256a[24:32])

	copy(aesIV[:8], sha256b[:8])
	copy(aesIV[8:24], sha256a[8:24])
	copy(aesIV[24:], sha256b[24:32])
	return
}

// Pow performs modular exponentiation: base^exp mod modulus.
func Pow(base, exp, modulus *big.Int) *big.Int {
	return new(big.Int).Exp(base, exp, modulus)
}

// Int64ToBytes converts int64 to 8-byte little-endian.
func Int64ToBytes(v int64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	return b
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}
