// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hpke

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"filippo.io/mlkem768"
)

func mustDecodeHex(t *testing.T, in string) []byte {
	t.Helper()
	b, err := hex.DecodeString(in)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVectors(t *testing.T) {
	t.Run("RFC9180", func(t *testing.T) {
		vectorsJSON, err := os.ReadFile("testdata/rfc9180.json")
		if err != nil {
			t.Fatal(err)
		}
		testVectors(t, vectorsJSON)
	})
	t.Run("hpke-pq", func(t *testing.T) {
		vectorsJSON, err := os.ReadFile("testdata/hpke-pq.json")
		if err != nil {
			t.Fatal(err)
		}
		testVectors(t, vectorsJSON)
	})
}

func testVectors(t *testing.T, vectorsJSON []byte) {
	var vectors []struct {
		Mode        uint16 `json:"mode"`
		KEM         uint16 `json:"kem_id"`
		KDF         uint16 `json:"kdf_id"`
		AEAD        uint16 `json:"aead_id"`
		Info        string `json:"info"`
		IkmE        string `json:"ikmE"`
		IkmR        string `json:"ikmR"`
		SkRm        string `json:"skRm"`
		PkRm        string `json:"pkRm"`
		Enc         string `json:"enc"`
		Encryptions []struct {
			Aad string `json:"aad"`
			Ct  string `json:"ct"`
			Pt  string `json:"pt"`
		} `json:"encryptions"`
		Exports []struct {
			Context string `json:"exporter_context"`
			L       int    `json:"L"`
			Value   string `json:"exported_value"`
		} `json:"exports"`
	}
	if err := json.Unmarshal(vectorsJSON, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, vector := range vectors {
		name := fmt.Sprintf("mode %04x kem %04x kdf %04x aead %04x",
			vector.Mode, vector.KEM, vector.KDF, vector.AEAD)
		t.Run(name, func(t *testing.T) {
			if vector.Mode != 0 {
				t.Skip("only mode 0 (base) is supported")
			}
			if vector.KEM == 0x0021 {
				t.Skip("KEM 0x0021 (DHKEM(X448)) not supported")
			}

			kdf, err := NewKDF(vector.KDF)
			if err != nil {
				t.Fatal(err)
			}
			if kdf.ID() != vector.KDF {
				t.Errorf("unexpected KDF ID: got %04x, want %04x", kdf.ID(), vector.KDF)
			}

			aead, err := NewAEAD(vector.AEAD)
			if err != nil {
				t.Fatal(err)
			}
			if aead.ID() != vector.AEAD {
				t.Errorf("unexpected AEAD ID: got %04x, want %04x", aead.ID(), vector.AEAD)
			}

			pubKeyBytes := mustDecodeHex(t, vector.PkRm)
			kemSender, err := UnstableNewKEMSender(vector.KEM, pubKeyBytes)
			if err != nil {
				t.Fatal(err)
			}
			if kemSender.ID() != vector.KEM {
				t.Errorf("unexpected KEM ID: got %04x, want %04x", kemSender.ID(), vector.KEM)
			}
			if !bytes.Equal(kemSender.Bytes(), pubKeyBytes) {
				t.Errorf("unexpected KEM bytes: got %x, want %x", kemSender.Bytes(), pubKeyBytes)
			}

			ikmE := mustDecodeHex(t, vector.IkmE)
			setupDerandomizedEncap(t, vector.KEM, ikmE, kemSender)

			info := mustDecodeHex(t, vector.Info)
			encap, sender, err := NewSender(kemSender, kdf, aead, info)
			if err != nil {
				t.Fatal(err)
			}

			expectedEncap := mustDecodeHex(t, vector.Enc)
			if !bytes.Equal(encap, expectedEncap) {
				t.Errorf("unexpected encapsulated key, got: %x, want %x", encap, expectedEncap)
			}

			privKeyBytes := mustDecodeHex(t, vector.SkRm)
			kemRecipient, err := UnstableNewKEMRecipient(vector.KEM, privKeyBytes)
			if err != nil {
				t.Fatal(err)
			}
			if kemRecipient.ID() != vector.KEM {
				t.Errorf("unexpected KEM ID: got %04x, want %04x", kemRecipient.ID(), vector.KEM)
			}
			kemRecipientBytes, err := kemRecipient.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			// X25519 serialized keys must be clamped, so the bytes might not match.
			if !bytes.Equal(kemRecipientBytes, privKeyBytes) && vector.KEM != 0x0020 {
				t.Errorf("unexpected KEM bytes: got %x, want %x", kemRecipientBytes, privKeyBytes)
			}
			if vector.KEM == 0x0020 {
				kem2, err := NewKEMRecipient(vector.KEM, kemRecipientBytes)
				if err != nil {
					t.Fatal(err)
				}
				kemRecipientBytes2, err := kem2.Bytes()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(kemRecipientBytes2, kemRecipientBytes) {
					t.Errorf("X25519 re-serialized key differs: got %x, want %x", kemRecipientBytes2, kemRecipientBytes)
				}
				if !bytes.Equal(kem2.KEMSender().Bytes(), pubKeyBytes) {
					t.Errorf("X25519 re-derived public key differs: got %x, want %x", kem2.KEMSender().Bytes(), pubKeyBytes)
				}
			}
			if !bytes.Equal(kemRecipient.KEMSender().Bytes(), pubKeyBytes) {
				t.Errorf("unexpected KEM sender bytes: got %x, want %x", kemRecipient.KEMSender().Bytes(), pubKeyBytes)
			}

			seed := mustDecodeHex(t, vector.IkmR)
			seedRecipient, err := UnstableNewKEMRecipientFromSeed(vector.KEM, seed)
			if err != nil {
				t.Fatal(err)
			}
			seedRecipientBytes, err := seedRecipient.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(seedRecipientBytes, privKeyBytes) && vector.KEM != 0x0020 {
				t.Errorf("unexpected KEM bytes from seed: got %x, want %x", seedRecipientBytes, privKeyBytes)
			}
			if !bytes.Equal(seedRecipient.KEMSender().Bytes(), pubKeyBytes) {
				t.Errorf("unexpected KEM sender bytes from seed: got %x, want %x", seedRecipient.KEMSender().Bytes(), pubKeyBytes)
			}

			recipient, err := NewRecipient(encap, kemRecipient, kdf, aead, info)
			if err != nil {
				t.Fatal(err)
			}

			for i, enc := range vector.Encryptions {
				name := fmt.Sprintf("encryption %d", i)
				t.Run(name, func(t *testing.T) {
					ciphertext, err := sender.Seal(mustDecodeHex(t, enc.Aad), mustDecodeHex(t, enc.Pt))
					if err != nil {
						t.Fatal(err)
					}
					expectedCiphertext := mustDecodeHex(t, enc.Ct)
					if !bytes.Equal(ciphertext, expectedCiphertext) {
						t.Errorf("unexpected ciphertext: got %x want %x", ciphertext, expectedCiphertext)
					}

					plaintext, err := recipient.Open(mustDecodeHex(t, enc.Aad), mustDecodeHex(t, enc.Ct))
					if err != nil {
						t.Fatal(err)
					}
					expectedPlaintext := mustDecodeHex(t, enc.Pt)
					if !bytes.Equal(plaintext, expectedPlaintext) {
						t.Errorf("unexpected plaintext: got %x want %x", plaintext, expectedPlaintext)
					}
				})
			}

			for i, exp := range vector.Exports {
				name := fmt.Sprintf("export %d", i)
				t.Run(name, func(t *testing.T) {
					expectedValue := mustDecodeHex(t, exp.Value)
					context := string(mustDecodeHex(t, exp.Context))

					exportedSender, err := sender.Export(context, exp.L)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(exportedSender, expectedValue) {
						t.Errorf("sender: unexpected exported secret: got %x want %x", exportedSender, expectedValue)
					}

					exportedRecipient, err := recipient.Export(context, exp.L)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(exportedRecipient, expectedValue) {
						t.Errorf("recipient: unexpected exported secret: got %x want %x", exportedRecipient, expectedValue)
					}
				})
			}
		})
	}
}

func setupDerandomizedEncap(t *testing.T, kemID uint16, randBytes []byte, kem KEMSender) {
	switch kemID {
	case 0x0010, 0x0011, 0x0012, 0x0020:
		r, err := NewKEMRecipientFromSeed(kemID, randBytes)
		if err != nil {
			t.Fatal(err)
		}
		testingOnlyGenerateKey = func() *ecdh.PrivateKey {
			return r.(*dhKEMRecipient).priv
		}
		t.Cleanup(func() {
			testingOnlyGenerateKey = nil
		})
	case 0x0050: // QSF-P256-MLKEM768-SHAKE256-SHA3256
		pqRand, tRand := randBytes[:32], randBytes[32:]
		k, err := ecdh.P256().NewPrivateKey(reduceScalar(tRand, p256Order))
		if err != nil {
			t.Fatal(err)
		}
		testingOnlyGenerateKey = func() *ecdh.PrivateKey {
			return k
		}
		testingOnlyEncapsulate = func() ([]byte, []byte) {
			ct, ss, err := mlkem768.EncapsulateDerand(kem.(*qsfSender).pq.Bytes(), pqRand)
			if err != nil {
				t.Fatal(err)
			}
			return ss, ct
		}
		t.Cleanup(func() {
			testingOnlyGenerateKey = nil
			testingOnlyEncapsulate = nil
		})
	case 0x647a: // QSF-X25519-MLKEM768-SHAKE256-SHA3256
		pqRand, tRand := randBytes[:32], randBytes[32:]
		k, err := ecdh.X25519().NewPrivateKey(tRand)
		if err != nil {
			t.Fatal(err)
		}
		testingOnlyGenerateKey = func() *ecdh.PrivateKey {
			return k
		}
		testingOnlyEncapsulate = func() ([]byte, []byte) {
			ct, ss, err := mlkem768.EncapsulateDerand(kem.(*qsfSender).pq.Bytes(), pqRand)
			if err != nil {
				t.Fatal(err)
			}
			return ss, ct
		}
		t.Cleanup(func() {
			testingOnlyGenerateKey = nil
			testingOnlyEncapsulate = nil
		})
	default:
		t.Fatalf("unsupported KEM %04x", kemID)
	}
}

func TestSingletons(t *testing.T) {
	if HKDFSHA256() != HKDFSHA256() {
		t.Error("HKDFSHA256() != HKDFSHA256()")
	}
	if HKDFSHA384() != HKDFSHA384() {
		t.Error("HKDFSHA384() != HKDFSHA384()")
	}
	if HKDFSHA512() != HKDFSHA512() {
		t.Error("HKDFSHA512() != HKDFSHA512()")
	}
	if AES128GCM() != AES128GCM() {
		t.Error("AES128GCM() != AES128GCM()")
	}
	if AES256GCM() != AES256GCM() {
		t.Error("AES256GCM() != AES256GCM()")
	}
	if ChaCha20Poly1305() != ChaCha20Poly1305() {
		t.Error("ChaCha20Poly1305() != ChaCha20Poly1305()")
	}
	if ExportOnly() != ExportOnly() {
		t.Error("ExportOnly() != ExportOnly()")
	}
}
