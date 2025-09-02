package hpke

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

type KEMSender interface {
	// ID returns the HPKE KEM identifier.
	ID() uint16

	// Bytes returns the public key as the output of SerializePublicKey.
	Bytes() []byte

	encap() (sharedSecret, enc []byte, err error)
}

// NewKEMSender implements DeserializePublicKey and returns a KEMSender
// for the given KEM ID and public key bytes.
func NewKEMSender(id uint16, pub []byte) (KEMSender, error) {
	switch id {
	case 0x0010: // DHKEM(P-256, HKDF-SHA256)
		k, err := ecdh.P256().NewPublicKey(pub)
		if err != nil {
			return nil, err
		}
		return DHKEMSender(k)
	case 0x0011: // DHKEM(P-384, HKDF-SHA384)
		k, err := ecdh.P384().NewPublicKey(pub)
		if err != nil {
			return nil, err
		}
		return DHKEMSender(k)
	case 0x0012: // DHKEM(P-521, HKDF-SHA512)
		k, err := ecdh.P521().NewPublicKey(pub)
		if err != nil {
			return nil, err
		}
		return DHKEMSender(k)
	case 0x0020: // DHKEM(X25519, HKDF-SHA256)
		k, err := ecdh.X25519().NewPublicKey(pub)
		if err != nil {
			return nil, err
		}
		return DHKEMSender(k)
	default:
		return nil, errors.New("unsupported KEM")
	}
}

type KEMRecipient interface {
	// ID returns the HPKE KEM identifier.
	ID() uint16

	// Bytes returns the private key as the output of SerializePrivateKey.
	//
	// Note that for X25519 this might not match the input to NewPrivateKey.
	// This is a requirement of RFC 9180, Section 7.1.2.
	Bytes() ([]byte, error)

	// KEMSender returns the corresponding KEMSender for this recipient.
	KEMSender() KEMSender

	decap(enc []byte) (sharedSecret []byte, err error)
}

// NewKEMRecipient implements DeserializePrivateKey and returns a KEMRecipient
// for the given KEM ID and private key bytes.
func NewKEMRecipient(id uint16, priv []byte) (KEMRecipient, error) {
	switch id {
	case 0x0010: // DHKEM(P-256, HKDF-SHA256)
		k, err := ecdh.P256().NewPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return DHKEMRecipient(k)
	case 0x0011: // DHKEM(P-384, HKDF-SHA384)
		k, err := ecdh.P384().NewPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return DHKEMRecipient(k)
	case 0x0012: // DHKEM(P-521, HKDF-SHA512)
		k, err := ecdh.P521().NewPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return DHKEMRecipient(k)
	case 0x0020: // DHKEM(X25519, HKDF-SHA256)
		k, err := ecdh.X25519().NewPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return DHKEMRecipient(k)
	default:
		return nil, errors.New("unsupported KEM")
	}
}

// NewKEMRecipientFromSeed implements DeriveKeyPair and returns a KEMRecipient
// for the given KEM ID and private key seed.
func NewKEMRecipientFromSeed(id uint16, priv []byte) (KEMRecipient, error) {
	// DeriveKeyPair from RFC 9180 Section 7.1.3.
	panic("not implemented") // TODO
}

type dhKEM struct {
	kdf     KDF
	id      uint16
	nSecret uint16
}

func (dh *dhKEM) extractAndExpand(dhKey, kemContext []byte) ([]byte, error) {
	suiteID := binary.BigEndian.AppendUint16([]byte("KEM"), dh.id)
	eaePRK, err := dh.kdf.labeledExtract(suiteID, nil, "eae_prk", dhKey)
	if err != nil {
		return nil, err
	}
	return dh.kdf.labeledExpand(suiteID, eaePRK, "shared_secret", kemContext, dh.nSecret)
}

func (dh *dhKEM) ID() uint16 {
	return dh.id
}

type dhKEMSender struct {
	dhKEM
	pub *ecdh.PublicKey
}

// DHKEMSender returns a KEMSender implementing one of
//
//   - DHKEM(P-256, HKDF-SHA256)
//   - DHKEM(P-384, HKDF-SHA384)
//   - DHKEM(P-521, HKDF-SHA512)
//   - DHKEM(X25519, HKDF-SHA256)
//
// depending on the underlying curve of the provided public key.
func DHKEMSender(pub *ecdh.PublicKey) (KEMSender, error) {
	dhKEM, err := dhKEMForCurve(pub.Curve())
	if err != nil {
		return nil, err
	}
	return &dhKEMSender{
		pub:   pub,
		dhKEM: dhKEM,
	}, nil
}

func dhKEMForCurve(curve ecdh.Curve) (dhKEM, error) {
	switch curve {
	case ecdh.P256():
		return dhKEM{
			kdf:     HKDFSHA256(),
			id:      0x0010,
			nSecret: 32,
		}, nil
	case ecdh.P384():
		return dhKEM{
			kdf:     HKDFSHA384(),
			id:      0x0011,
			nSecret: 48,
		}, nil
	case ecdh.P521():
		return dhKEM{
			kdf:     HKDFSHA512(),
			id:      0x0012,
			nSecret: 64,
		}, nil
	case ecdh.X25519():
		return dhKEM{
			kdf:     HKDFSHA256(),
			id:      0x0020,
			nSecret: 32,
		}, nil
	default:
		return dhKEM{}, errors.New("unsupported curve")
	}
}

func (dh *dhKEMSender) Bytes() []byte {
	return dh.pub.Bytes()
}

// testingOnlyGenerateKey is only used during testing, to provide
// a fixed test key to use when checking the RFC 9180 vectors.
var testingOnlyGenerateKey func() *ecdh.PrivateKey

func (dh *dhKEMSender) encap() (sharedSecret []byte, encapPub []byte, err error) {
	privEph, err := dh.pub.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if testingOnlyGenerateKey != nil {
		privEph = testingOnlyGenerateKey()
	}
	dhVal, err := privEph.ECDH(dh.pub)
	if err != nil {
		return nil, nil, err
	}
	encPubEph := privEph.PublicKey().Bytes()

	encPubRecip := dh.pub.Bytes()
	kemContext := append(encPubEph, encPubRecip...)
	sharedSecret, err = dh.extractAndExpand(dhVal, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return sharedSecret, encPubEph, nil
}

type dhKEMRecipient struct {
	dhKEM
	priv *ecdh.PrivateKey
}

// DHKEMRecipient returns a KEMRecipient implementing one of
//
//   - DHKEM(P-256, HKDF-SHA256)
//   - DHKEM(P-384, HKDF-SHA384)
//   - DHKEM(P-521, HKDF-SHA512)
//   - DHKEM(X25519, HKDF-SHA256)
//
// depending on the underlying curve of the provided private key.
func DHKEMRecipient(priv *ecdh.PrivateKey) (KEMRecipient, error) {
	dhKEM, err := dhKEMForCurve(priv.Curve())
	if err != nil {
		return nil, err
	}
	return &dhKEMRecipient{
		priv:  priv,
		dhKEM: dhKEM,
	}, nil
}

func (dh *dhKEMRecipient) Bytes() ([]byte, error) {
	// Bizarrely, RFC 9180, Section 7.1.2 says SerializePrivateKey MUST clamp
	// the output, which I thought we all agreed to instead do as part of the DH
	// function, letting private keys be random bytes.
	//
	// At the same time, DeserializePrivateKey MUST also clamp, implying
	// that the input doesn't have to be clamped, so Bytes by spec doesn't
	// necessarily match the NewPrivateKey input.
	//
	// Sigh.
	if dh.id == 0x0020 { // X25519
		b := dh.priv.Bytes()
		b[0] &= 248
		b[31] &= 127
		b[31] |= 64
		return b, nil
	}
	return dh.priv.Bytes(), nil
}

func (dh *dhKEMRecipient) KEMSender() KEMSender {
	return &dhKEMSender{
		pub:   dh.priv.PublicKey(),
		dhKEM: dh.dhKEM,
	}
}

func (dh *dhKEMRecipient) decap(encPubEph []byte) ([]byte, error) {
	pubEph, err := dh.priv.Curve().NewPublicKey(encPubEph)
	if err != nil {
		return nil, err
	}
	dhVal, err := dh.priv.ECDH(pubEph)
	if err != nil {
		return nil, err
	}
	kemContext := append(encPubEph, dh.priv.PublicKey().Bytes()...)
	return dh.extractAndExpand(dhVal, kemContext)
}
