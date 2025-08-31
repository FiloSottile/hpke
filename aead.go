package hpke

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

type AEAD interface {
	ID() uint16
	keySize() int
	nonceSize() int
	aead(key []byte) (cipher.AEAD, error)
}

func NewAEAD(id uint16) (AEAD, error) {
	switch id {
	case 0x0001: // AES-128-GCM
		return AES128GCM(), nil
	case 0x0002: // AES-256-GCM
		return AES256GCM(), nil
	case 0x0003: // ChaCha20Poly1305
		return ChaCha20Poly1305(), nil
	case 0xFFFF: // Export-only
		return ExportOnly(), nil
	default:
		return nil, fmt.Errorf("unsupported AEAD %04x", id)
	}
}

func AES128GCM() AEAD        { return aes128GCM }
func AES256GCM() AEAD        { return aes256GCM }
func ChaCha20Poly1305() AEAD { return chacha20poly1305AEAD }
func ExportOnly() AEAD       { return exportOnlyAEAD{} }

type aead struct {
	nK  int
	nN  int
	new func([]byte) (cipher.AEAD, error)
	id  uint16
}

var aes128GCM = &aead{
	nK:  128 / 8,
	nN:  96 / 8,
	new: newAESGCM,
	id:  0x0001,
}

var aes256GCM = &aead{
	nK:  256 / 8,
	nN:  96 / 8,
	new: newAESGCM,
	id:  0x0002,
}

var chacha20poly1305AEAD = &aead{
	nK:  chacha20poly1305.KeySize,
	nN:  chacha20poly1305.NonceSize,
	new: chacha20poly1305.New,
	id:  0x0003,
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func (a *aead) ID() uint16 {
	return a.id
}

func (a *aead) aead(key []byte) (cipher.AEAD, error) {
	if len(key) != a.nK {
		return nil, errors.New("invalid key size")
	}
	return a.new(key)
}

func (a *aead) keySize() int {
	return a.nK
}

func (a *aead) nonceSize() int {
	return a.nN
}

type exportOnlyAEAD struct{}

func (exportOnlyAEAD) ID() uint16 {
	return 0xFFFF
}

func (exportOnlyAEAD) aead(key []byte) (cipher.AEAD, error) {
	return nil, nil
}

func (exportOnlyAEAD) keySize() int {
	return 0
}

func (exportOnlyAEAD) nonceSize() int {
	return 0
}
