package hpke

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"errors"

	"filippo.io/bigmod"
)

func UnstableNewKEMSender(id uint16, pub []byte) (KEMSender, error) {
	switch id {
	case 0x0050: // QSF-P256-MLKEM768-SHAKE256-SHA3256
		if len(pub) != mlkem.EncapsulationKeySize768+65 {
			return nil, errors.New("invalid public key size")
		}
		pq, err := mlkem.NewEncapsulationKey768(pub[:mlkem.EncapsulationKeySize768])
		if err != nil {
			return nil, err
		}
		k, err := ecdh.P256().NewPublicKey(pub[mlkem.EncapsulationKeySize768:])
		if err != nil {
			return nil, err
		}
		return QSFSender(k, pq)
	case 0x647a: // QSF-X25519-MLKEM768-SHAKE256-SHA3256
		if len(pub) != mlkem.EncapsulationKeySize768+32 {
			return nil, errors.New("invalid public key size")
		}
		pq, err := mlkem.NewEncapsulationKey768(pub[:mlkem.EncapsulationKeySize768])
		if err != nil {
			return nil, err
		}
		k, err := ecdh.X25519().NewPublicKey(pub[mlkem.EncapsulationKeySize768:])
		if err != nil {
			return nil, err
		}
		return QSFSender(k, pq)
	default:
		return NewKEMSender(id, pub)
	}
}

func UnstableNewKEMRecipient(id uint16, priv []byte) (KEMRecipient, error) {
	switch id {
	case 0x0050: // QSF-P256-MLKEM768-SHAKE256-SHA3256
		if len(priv) != 32 {
			return nil, errors.New("invalid private key size")
		}
		s := sha3.NewSHAKE256()
		s.Write(priv)
		exp := make([]byte, mlkem.SeedSize+48)
		s.Read(exp)

		pq, err := mlkem.NewDecapsulationKey768(exp[:mlkem.SeedSize])
		if err != nil {
			return nil, err
		}
		k, err := ecdh.P256().NewPrivateKey(reduceScalar(exp[mlkem.SeedSize:], p256Order))
		if err != nil {
			return nil, err
		}
		return qsfRecipientWithSeed(k, pq, priv)
	case 0x647a: // QSF-X25519-MLKEM768-SHAKE256-SHA3256
		if len(priv) != 32 {
			return nil, errors.New("invalid private key size")
		}
		s := sha3.NewSHAKE256()
		s.Write(priv)
		exp := make([]byte, mlkem.SeedSize+32)
		s.Read(exp)

		pq, err := mlkem.NewDecapsulationKey768(exp[:mlkem.SeedSize])
		if err != nil {
			return nil, err
		}
		k, err := ecdh.X25519().NewPrivateKey(exp[mlkem.SeedSize:])
		if err != nil {
			return nil, err
		}
		return qsfRecipientWithSeed(k, pq, priv)
	default:
		return NewKEMRecipient(id, priv)
	}
}

func UnstableNewKEMRecipientFromSeed(id uint16, seed []byte) (KEMRecipient, error) {
	switch id {
	case 0x0050, 0x647a:
		// For QSF, the decapsulation key and the seed are the same.
		return UnstableNewKEMRecipient(id, seed)
	default:
		return NewKEMRecipientFromSeed(id, seed)
	}
}

type qsf struct {
	id    uint16
	label string
}

func (q *qsf) ID() uint16 {
	return q.id
}

func (q *qsf) sharedSecret(ssPQ, ssT, ctT, ekT []byte) []byte {
	h := sha3.New256()
	h.Write(ssPQ)
	h.Write(ssT)
	h.Write(ctT)
	h.Write(ekT)
	h.Write([]byte(q.label))
	return h.Sum(nil)
}

type qsfSender struct {
	qsf
	t  *ecdh.PublicKey
	pq *mlkem.EncapsulationKey768
}

// QSFSender returns a KEMSender implementing QSF-P256-MLKEM768-SHAKE256-SHA3256
// or QSF-X25519-MLKEM768-SHA3256-SHAKE256 (aka X-Wing) from draft-ietf-hpke-pq
// and draft-irtf-cfrg-concrete-hybrid-kems-00.
func QSFSender(t *ecdh.PublicKey, pq *mlkem.EncapsulationKey768) (KEMSender, error) {
	switch t.Curve() {
	case ecdh.P256():
		return &qsfSender{
			t: t, pq: pq,
			qsf: qsf{
				id:    0x0050,
				label: "QSF-P256-MLKEM768-SHAKE256-SHA3256",
			},
		}, nil
	case ecdh.X25519():
		return &qsfSender{
			t: t, pq: pq,
			qsf: qsf{
				id: 0x647a,
				label: /**/ `\./` +
					/*   */ `/^\`,
			},
		}, nil
	default:
		return nil, errors.New("unsupported curve")
	}
}

func (s *qsfSender) Bytes() []byte {
	return append(s.pq.Bytes(), s.t.Bytes()...)
}

var testingOnlyEncapsulate func() (ss, ct []byte)

func (s *qsfSender) encap() (sharedSecret []byte, encapPub []byte, err error) {
	skE, err := s.t.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if testingOnlyGenerateKey != nil {
		skE = testingOnlyGenerateKey()
	}
	ssT, err := skE.ECDH(s.t)
	if err != nil {
		return nil, nil, err
	}
	ctT := skE.PublicKey().Bytes()

	ssPQ, ctPQ := s.pq.Encapsulate()
	if testingOnlyEncapsulate != nil {
		ssPQ, ctPQ = testingOnlyEncapsulate()
	}

	ss := s.sharedSecret(ssPQ, ssT, ctT, s.t.Bytes())
	ct := append(ctPQ, ctT...)
	return ss, ct, nil
}

type qsfRecipient struct {
	qsf
	seed []byte // can be nil
	t    *ecdh.PrivateKey
	pq   *mlkem.DecapsulationKey768
}

// QSFRecipient returns a KEMRecipient implementing QSF-P256-MLKEM768-SHAKE256-SHA3256
// or QSF-MLKEM768-X25519-SHA3256-SHAKE256 (aka X-Wing) from draft-ietf-hpke-pq
// and draft-irtf-cfrg-concrete-hybrid-kems-00.
func QSFRecipient(t *ecdh.PrivateKey, pq *mlkem.DecapsulationKey768) (KEMRecipient, error) {
	return qsfRecipientWithSeed(t, pq, nil)
}

func qsfRecipientWithSeed(t *ecdh.PrivateKey, pq *mlkem.DecapsulationKey768, seed []byte) (KEMRecipient, error) {
	switch t.Curve() {
	case ecdh.P256():
		return &qsfRecipient{
			t: t, pq: pq, seed: bytes.Clone(seed),
			qsf: qsf{
				id:    0x0050,
				label: "QSF-P256-MLKEM768-SHAKE256-SHA3256",
			},
		}, nil
	case ecdh.X25519():
		return &qsfRecipient{
			t: t, pq: pq, seed: bytes.Clone(seed),
			qsf: qsf{
				id: 0x647a,
				label: /**/ `\./` +
					/*   */ `/^\`,
			},
		}, nil
	default:
		return nil, errors.New("unsupported curve")
	}
}

func (r *qsfRecipient) Bytes() ([]byte, error) {
	if r.seed == nil {
		return nil, errors.New("private key seed not available")
	}
	return r.seed, nil
}

func (r *qsfRecipient) KEMSender() KEMSender {
	return &qsfSender{
		qsf: r.qsf,
		t:   r.t.PublicKey(),
		pq:  r.pq.EncapsulationKey(),
	}
}

func (r *qsfRecipient) decap(enc []byte) ([]byte, error) {
	ctPQ, ctT := enc[:mlkem.CiphertextSize768], enc[mlkem.CiphertextSize768:]
	ssPQ, err := r.pq.Decapsulate(ctPQ)
	if err != nil {
		return nil, err
	}
	pub, err := r.t.Curve().NewPublicKey(ctT)
	if err != nil {
		return nil, err
	}
	ssT, err := r.t.ECDH(pub)
	if err != nil {
		return nil, err
	}
	ss := r.sharedSecret(ssPQ, ssT, ctT, r.t.PublicKey().Bytes())
	return ss, nil
}

func reduceScalar(ikm []byte, order *bigmod.Modulus) []byte {
	mb := append([]byte{0b10}, bytes.Repeat([]byte{0}, len(ikm))...)
	m, err := bigmod.NewModulus(mb)
	if err != nil {
		panic(err)
	}
	s, err := bigmod.NewNat().SetBytes(ikm, m)
	if err != nil {
		panic(err)
	}
	return bigmod.NewNat().Mod(s, order).Bytes(order)
}

var p256Order, _ = bigmod.NewModulus([]byte{
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
	0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
})

var p384Order, _ = bigmod.NewModulus([]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
	0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a,
	0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
})
