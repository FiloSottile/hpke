// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hpke

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math/bits"
)

type context struct {
	suiteID []byte

	export func(string, uint16) ([]byte, error)

	aead      cipher.AEAD
	baseNonce []byte
	seqNum    uint128
}

type Sender struct {
	*context
}

type Recipient struct {
	*context
}

func newContext(sharedSecret []byte, kemID uint16, kdf KDF, aead AEAD, info []byte) (*context, error) {
	sid := suiteID(kemID, kdf.ID(), aead.ID())

	pskIDHash, err := kdf.labeledExtract(sid, nil, "psk_id_hash", nil)
	if err != nil {
		return nil, err
	}
	infoHash, err := kdf.labeledExtract(sid, nil, "info_hash", info)
	if err != nil {
		return nil, err
	}
	ksContext := append([]byte{0}, pskIDHash...)
	ksContext = append(ksContext, infoHash...)

	secret, err := kdf.labeledExtract(sid, sharedSecret, "secret", nil)
	if err != nil {
		return nil, err
	}
	key, err := kdf.labeledExpand(sid, secret, "key", ksContext, uint16(aead.keySize()))
	if err != nil {
		return nil, err
	}
	a, err := aead.aead(key)
	if err != nil {
		return nil, err
	}
	baseNonce, err := kdf.labeledExpand(sid, secret, "base_nonce", ksContext, uint16(aead.nonceSize()))
	if err != nil {
		return nil, err
	}
	expSecret, err := kdf.labeledExpand(sid, secret, "exp", ksContext, uint16(len(secret)))
	if err != nil {
		return nil, err
	}
	export := func(exporterContext string, length uint16) ([]byte, error) {
		return kdf.labeledExpand(sid, expSecret, "sec", []byte(exporterContext), length)
	}

	return &context{
		aead:      a,
		suiteID:   sid,
		export:    export,
		baseNonce: baseNonce,
	}, nil
}

func NewSender(kem KEMSender, kdf KDF, aead AEAD, info []byte) ([]byte, *Sender, error) {
	sharedSecret, encapsulatedKey, err := kem.encap()
	if err != nil {
		return nil, nil, err
	}
	context, err := newContext(sharedSecret, kem.ID(), kdf, aead, info)
	if err != nil {
		return nil, nil, err
	}
	return encapsulatedKey, &Sender{context}, nil
}

func NewRecipient(enc []byte, kem KEMRecipient, kdf KDF, aead AEAD, info []byte) (*Recipient, error) {
	sharedSecret, err := kem.decap(enc)
	if err != nil {
		return nil, err
	}
	context, err := newContext(sharedSecret, kem.ID(), kdf, aead, info)
	if err != nil {
		return nil, err
	}
	return &Recipient{context}, nil
}

func (s *Sender) Seal(aad, plaintext []byte) ([]byte, error) {
	if s.aead == nil {
		return nil, errors.New("export-only instantiation")
	}
	ciphertext := s.aead.Seal(nil, s.nextNonce(), plaintext, aad)
	s.incrementNonce()
	return ciphertext, nil
}

func Seal(kem KEMSender, kdf KDF, aead AEAD, info, plaintext []byte) (enc, ct []byte, err error) {
	enc, s, err := NewSender(kem, kdf, aead, info)
	if err != nil {
		return nil, nil, err
	}
	ct, err = s.Seal(nil, plaintext)
	if err != nil {
		return nil, nil, err
	}
	return enc, ct, err
}

func (s *Sender) Export(exporterContext string, length int) ([]byte, error) {
	if length < 0 || length > 0xFFFF {
		return nil, errors.New("invalid length")
	}
	return s.export(exporterContext, uint16(length))
}

func (r *Recipient) Open(aad, ciphertext []byte) ([]byte, error) {
	if r.aead == nil {
		return nil, errors.New("export-only instantiation")
	}
	plaintext, err := r.aead.Open(nil, r.nextNonce(), ciphertext, aad)
	if err != nil {
		return nil, err
	}
	r.incrementNonce()
	return plaintext, nil
}

func Open(enc []byte, kem KEMRecipient, kdf KDF, aead AEAD, info, ciphertext []byte) ([]byte, error) {
	r, err := NewRecipient(enc, kem, kdf, aead, info)
	if err != nil {
		return nil, err
	}
	return r.Open(nil, ciphertext)
}

func (r *Recipient) Export(exporterContext string, length int) ([]byte, error) {
	if length < 0 || length > 0xFFFF {
		return nil, errors.New("invalid length")
	}
	return r.export(exporterContext, uint16(length))
}

func (ctx *context) nextNonce() []byte {
	nonce := ctx.seqNum.bytes()[16-ctx.aead.NonceSize():]
	for i := range ctx.baseNonce {
		nonce[i] ^= ctx.baseNonce[i]
	}
	return nonce
}

func (ctx *context) incrementNonce() {
	ctx.seqNum = ctx.seqNum.addOne()
}

func suiteID(kemID, kdfID, aeadID uint16) []byte {
	suiteID := make([]byte, 0, 4+2+2+2)
	suiteID = append(suiteID, []byte("HPKE")...)
	suiteID = binary.BigEndian.AppendUint16(suiteID, kemID)
	suiteID = binary.BigEndian.AppendUint16(suiteID, kdfID)
	suiteID = binary.BigEndian.AppendUint16(suiteID, aeadID)
	return suiteID
}

type uint128 struct {
	hi, lo uint64
}

func (u uint128) addOne() uint128 {
	lo, carry := bits.Add64(u.lo, 1, 0)
	return uint128{u.hi + carry, lo}
}

func (u uint128) bytes() []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[0:], u.hi)
	binary.BigEndian.PutUint64(b[8:], u.lo)
	return b
}
