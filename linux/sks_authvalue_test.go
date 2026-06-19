//go:build linux
// +build linux

// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linux

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpmutil"
)

// newSimDevice returns a tpmDevice backed by an in-process TPM simulator and an
// isolated on-disk key store, suitable for exercising the key operations.
func newSimDevice(t *testing.T) *tpmDevice {
	t.Helper()
	// diskio.OpenDB resolves its location once from XDG_DATA_HOME; point it at a
	// throwaway directory so the test does not touch a real key store.
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	sim, err := simulator.Get()
	if err != nil {
		t.Fatalf("failed to start TPM simulator: %v", err)
	}
	t.Cleanup(func() { sim.Close() })

	return &tpmDevice{
		rwc:        sim,
		keyHandler: NewKeyHandler(map[string]tpmutil.Handle{}),
	}
}

// verifyP256 reports whether sig is a valid ASN.1 DER ECDSA signature over
// digest for the P-256 public key marshalled as raw X || Y in pubRaw.
func verifyP256(pubRaw, digest, sig []byte) bool {
	x, y := elliptic.Unmarshal(elliptic.P256(), pubRaw)
	if x == nil {
		return false
	}
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		return false
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	return ecdsa.Verify(pub, digest, parsed.R, parsed.S)
}

// TestSignWithKeyAuthValue checks that a key created with an authValue requires
// that same value to sign: the correct value produces a verifiable signature
// and a wrong value is rejected by the TPM.
func TestSignWithKeyAuthValue(t *testing.T) {
	tpm := newSimDevice(t)

	const keyID = "auth-value-key"
	authValue := []byte("1234")

	pubRaw, err := tpm.GenKeyPair(keyID, authValue)
	if err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}

	digest := sha256.Sum256([]byte("the quick brown fox"))

	sig, err := tpm.SignWithKey(keyID, digest[:], authValue)
	if err != nil {
		t.Fatalf("SignWithKey with the correct auth value: %v", err)
	}
	if !verifyP256(pubRaw, digest[:], sig) {
		t.Error("signature did not verify against the returned public key")
	}

	if _, err := tpm.SignWithKey(keyID, digest[:], []byte("wrong")); err == nil {
		t.Error("SignWithKey with a wrong auth value succeeded, want failure")
	}
}

// TestSignWithKeyNoAuthValue checks that the presence-less path is unchanged: a
// key created without an authValue signs with an empty one.
func TestSignWithKeyNoAuthValue(t *testing.T) {
	tpm := newSimDevice(t)

	const keyID = "no-auth-value-key"

	pubRaw, err := tpm.GenKeyPair(keyID, nil)
	if err != nil {
		t.Fatalf("GenKeyPair: %v", err)
	}

	digest := sha256.Sum256([]byte("lazy dog"))

	sig, err := tpm.SignWithKey(keyID, digest[:], nil)
	if err != nil {
		t.Fatalf("SignWithKey: %v", err)
	}
	if !verifyP256(pubRaw, digest[:], sig) {
		t.Error("signature did not verify against the returned public key")
	}
}
