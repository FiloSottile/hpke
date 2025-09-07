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

// UnstableNewKEMSender extends [NewKEMSender] to also implement
//
//   - ML-KEM-768
//   - ML-KEM-1024
//   - QSF-P256-MLKEM768-SHAKE256-SHA3256
//   - QSF-P384-MLKEM1024-SHAKE256-SHA3256
//   - QSF-X25519-MLKEM768-SHAKE256-SHA3256 (a.k.a. X-Wing)
//
// from draft-ietf-hpke-pq. Their implementation may still change while the
// document is in draft status.
func UnstableNewKEMSender(id uint16, pub []byte) (KEMSender, error) {
	switch id {
	case 0x0041: // ML-KEM-768
		if len(pub) != mlkem.EncapsulationKeySize768 {
			return nil, errors.New("invalid public key size")
		}
		pq, err := mlkem.NewEncapsulationKey768(pub)
		if err != nil {
			return nil, err
		}
		return MLKEMSender(pq), nil
	case 0x0042: // ML-KEM-1024
		if len(pub) != mlkem.EncapsulationKeySize1024 {
			return nil, errors.New("invalid public key size")
		}
		pq, err := mlkem.NewEncapsulationKey1024(pub)
		if err != nil {
			return nil, err
		}
		return MLKEMSender(pq), nil
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
	case 0x0051: // QSF-P384-MLKEM1024-SHAKE256-SHA3256
		if len(pub) != mlkem.EncapsulationKeySize1024+97 {
			return nil, errors.New("invalid public key size")
		}
		pq, err := mlkem.NewEncapsulationKey1024(pub[:mlkem.EncapsulationKeySize1024])
		if err != nil {
			return nil, err
		}
		k, err := ecdh.P384().NewPublicKey(pub[mlkem.EncapsulationKeySize1024:])
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

// UnstableNewKEMRecipient extends [NewKEMRecipient] to also implement
//
//   - ML-KEM-768
//   - ML-KEM-1024
//   - QSF-P256-MLKEM768-SHAKE256-SHA3256
//   - QSF-P384-MLKEM1024-SHAKE256-SHA3256
//   - QSF-X25519-MLKEM768-SHAKE256-SHA3256 (a.k.a. X-Wing)
//
// from draft-ietf-hpke-pq. Their implementation may still change while the
// document is in draft status.
func UnstableNewKEMRecipient(id uint16, priv []byte) (KEMRecipient, error) {
	switch id {
	case 0x0041: // ML-KEM-768
		if len(priv) != mlkem.SeedSize {
			return nil, errors.New("invalid private key size")
		}
		pq, err := mlkem.NewDecapsulationKey768(priv)
		if err != nil {
			return nil, err
		}
		return MLKEMRecipient(pq), nil
	case 0x0042: // ML-KEM-1024
		if len(priv) != mlkem.SeedSize {
			return nil, errors.New("invalid private key size")
		}
		pq, err := mlkem.NewDecapsulationKey1024(priv)
		if err != nil {
			return nil, err
		}
		return MLKEMRecipient(pq), nil
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
	case 0x0051: // QSF-P384-MLKEM1024-SHAKE256-SHA3256
		if len(priv) != 32 {
			return nil, errors.New("invalid private key size")
		}
		s := sha3.NewSHAKE256()
		s.Write(priv)
		exp := make([]byte, mlkem.SeedSize+72)
		s.Read(exp)

		pq, err := mlkem.NewDecapsulationKey1024(exp[:mlkem.SeedSize])
		if err != nil {
			return nil, err
		}
		k, err := ecdh.P384().NewPrivateKey(reduceScalar(exp[mlkem.SeedSize:], p384Order))
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

// UnstableNewKEMRecipientFromSeed extends [NewKEMRecipientFromSeed] to also
// implement
//
//   - ML-KEM-768
//   - ML-KEM-1024
//   - QSF-P256-MLKEM768-SHAKE256-SHA3256
//   - QSF-P384-MLKEM1024-SHAKE256-SHA3256
//   - QSF-X25519-MLKEM768-SHAKE256-SHA3256 (a.k.a. X-Wing)
//
// from draft-ietf-hpke-pq. Their implementation may still change while the
// document is in draft status.
//
// Note that at the moment, the private key for all those KEMs is the same as
// the seed, and unlike DHKEM the seed must have a fixed per-KEM length.
func UnstableNewKEMRecipientFromSeed(id uint16, seed []byte) (KEMRecipient, error) {
	switch id {
	case 0x0041, 0x0042, 0x0050, 0x0051, 0x647a:
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
	pq interface {
		Bytes() []byte
		Encapsulate() (sharedKey []byte, ciphertext []byte)
	}
}

// QSFSender returns a KEMSender implementing one of
//
//   - QSF-P256-MLKEM768-SHAKE256-SHA3256
//   - QSF-P384-MLKEM1024-SHAKE256-SHA3256
//   - QSF-X25519-MLKEM768-SHA3256-SHAKE256 (a.k.a. X-Wing)
//
// from draft-ietf-hpke-pq, depending on the underlying curve of t.
func QSFSender[EK MLKEMEncapsulationKey](t *ecdh.PublicKey, pq EK) (KEMSender, error) {
	switch t.Curve() {
	case ecdh.P256():
		return &qsfSender{
			t: t, pq: pq,
			qsf: qsf{
				id:    0x0050,
				label: "QSF-P256-MLKEM768-SHAKE256-SHA3256",
			},
		}, nil
	case ecdh.P384():
		return &qsfSender{
			t: t, pq: pq,
			qsf: qsf{
				id:    0x0051,
				label: "QSF-P384-MLKEM1024-SHAKE256-SHA3256",
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

type qsfRecipient[EK MLKEMEncapsulationKey] struct {
	qsf
	seed []byte // can be nil
	t    ECDHPrivateKey
	pq   MLKEMDecapsulationKey[EK]
}

type MLKEMEncapsulationKey interface {
	*mlkem.EncapsulationKey768 | *mlkem.EncapsulationKey1024
	Bytes() []byte
	Encapsulate() (sharedKey []byte, ciphertext []byte)
}

type MLKEMDecapsulationKey[EK MLKEMEncapsulationKey] interface {
	Decapsulate(ciphertext []byte) (sharedKey []byte, err error)
	EncapsulationKey() EK
}

// QSFRecipient returns a KEMRecipient implementing one of
//
//   - QSF-P256-MLKEM768-SHAKE256-SHA3256
//   - QSF-P384-MLKEM1024-SHAKE256-SHA3256
//   - QSF-X25519-MLKEM768-SHA3256-SHAKE256 (a.k.a. X-Wing)
//
// from draft-ietf-hpke-pq, depending on the underlying curve of t.
func QSFRecipient[EK MLKEMEncapsulationKey](t ECDHPrivateKey, pq MLKEMDecapsulationKey[EK]) (KEMRecipient, error) {
	return qsfRecipientWithSeed(t, pq, nil)
}

func qsfRecipientWithSeed[EK MLKEMEncapsulationKey](t ECDHPrivateKey, pq MLKEMDecapsulationKey[EK], seed []byte) (KEMRecipient, error) {
	switch t.Curve() {
	case ecdh.P256():
		return &qsfRecipient[EK]{
			t: t, pq: pq, seed: bytes.Clone(seed),
			qsf: qsf{
				id:    0x0050,
				label: "QSF-P256-MLKEM768-SHAKE256-SHA3256",
			},
		}, nil
	case ecdh.P384():
		return &qsfRecipient[EK]{
			t: t, pq: pq, seed: bytes.Clone(seed),
			qsf: qsf{
				id:    0x0051,
				label: "QSF-P384-MLKEM1024-SHAKE256-SHA3256",
			},
		}, nil
	case ecdh.X25519():
		return &qsfRecipient[EK]{
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

func (r *qsfRecipient[EK]) Bytes() ([]byte, error) {
	if r.seed == nil {
		return nil, errors.New("private key seed not available")
	}
	return r.seed, nil
}

func (r *qsfRecipient[EK]) KEMSender() KEMSender {
	return &qsfSender{
		qsf: r.qsf,
		t:   r.t.PublicKey(),
		pq:  r.pq.EncapsulationKey(),
	}
}

func (r *qsfRecipient[EK]) decap(enc []byte) ([]byte, error) {
	var ctPQ, ctT []byte
	switch r.id {
	case 0x0050:
		if len(enc) != mlkem.CiphertextSize768+65 {
			return nil, errors.New("invalid encapsulated key size")
		}
		ctPQ, ctT = enc[:mlkem.CiphertextSize768], enc[mlkem.CiphertextSize768:]
	case 0x0051:
		if len(enc) != mlkem.CiphertextSize1024+97 {
			return nil, errors.New("invalid encapsulated key size")
		}
		ctPQ, ctT = enc[:mlkem.CiphertextSize1024], enc[mlkem.CiphertextSize1024:]
	case 0x647a:
		if len(enc) != mlkem.CiphertextSize768+32 {
			return nil, errors.New("invalid encapsulated key size")
		}
		ctPQ, ctT = enc[:mlkem.CiphertextSize768], enc[mlkem.CiphertextSize768:]
	default:
		return nil, errors.New("internal error: unsupported KEM")
	}
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

type mlkemSender struct {
	id uint16
	pq interface {
		Bytes() []byte
		Encapsulate() (sharedKey []byte, ciphertext []byte)
	}
}

// MLKEMSender returns a KEMSender implementing ML-KEM-768 or ML-KEM-1024 from
// draft-ietf-hpke-pq.
func MLKEMSender[EK MLKEMEncapsulationKey](pq EK) KEMSender {
	switch any(pq).(type) {
	case *mlkem.EncapsulationKey768:
		return &mlkemSender{
			id: 0x0041,
			pq: pq,
		}
	case *mlkem.EncapsulationKey1024:
		return &mlkemSender{
			id: 0x0042,
			pq: pq,
		}
	}
	panic("unreachable: generic type must be either *mlkem.EncapsulationKey768 or *mlkem.EncapsulationKey1024")
}

func (s *mlkemSender) ID() uint16 {
	return s.id
}

func (s *mlkemSender) Bytes() []byte {
	return s.pq.Bytes()
}

func (s *mlkemSender) encap() (sharedSecret []byte, encapPub []byte, err error) {
	ss, ct := s.pq.Encapsulate()
	if testingOnlyEncapsulate != nil {
		ss, ct = testingOnlyEncapsulate()
	}
	return ss, ct, nil
}

type mlkemRecipient[EK MLKEMEncapsulationKey] struct {
	id uint16
	pq MLKEMDecapsulationKey[EK]
}

// MLKEMRecipient returns a KEMRecipient implementing ML-KEM-768 or ML-KEM-1024
// from draft-ietf-hpke-pq.
func MLKEMRecipient[EK MLKEMEncapsulationKey](pq MLKEMDecapsulationKey[EK]) KEMRecipient {
	switch any(pq.EncapsulationKey()).(type) {
	case *mlkem.EncapsulationKey768:
		return &mlkemRecipient[EK]{
			id: 0x0041,
			pq: pq,
		}
	case *mlkem.EncapsulationKey1024:
		return &mlkemRecipient[EK]{
			id: 0x0042,
			pq: pq,
		}
	default:
		panic("unreachable: generic type must be either *mlkem.EncapsulationKey768 or *mlkem.EncapsulationKey1024")
	}
}

func (r *mlkemRecipient[EK]) ID() uint16 {
	return r.id
}

func (r *mlkemRecipient[EK]) Bytes() ([]byte, error) {
	pq, ok := r.pq.(interface {
		Bytes() []byte
	})
	if !ok {
		return nil, errors.New("private key seed not available")
	}
	return pq.Bytes(), nil
}

func (r *mlkemRecipient[EK]) KEMSender() KEMSender {
	s := &mlkemSender{
		id: r.id,
		pq: r.pq.EncapsulationKey(),
	}
	return s
}

func (r *mlkemRecipient[EK]) decap(enc []byte) ([]byte, error) {
	switch r.id {
	case 0x0041:
		if len(enc) != mlkem.CiphertextSize768 {
			return nil, errors.New("invalid encapsulated key size")
		}
	case 0x0042:
		if len(enc) != mlkem.CiphertextSize1024 {
			return nil, errors.New("invalid encapsulated key size")
		}
	default:
		return nil, errors.New("internal error: unsupported KEM")
	}
	return r.pq.Decapsulate(enc)
}
