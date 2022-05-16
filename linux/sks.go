//go:build linux
// +build linux

// Copyright (c) Facebook, Inc. and its affiliates.
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
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"

	"github.com/facebookincubator/sks/diskio"
	"github.com/facebookincubator/sks/utils"

	"github.com/facebookincubator/flog"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// This file defines the public interface of SKS for Linux. The implementation
// of the functions exposed in sks_linux.go are defined here. This is the only
// exception to having all TPM device functions in tpm.go and exists solely for
// keeping the public SKS API in one easily-discovered location.
func (tpm *tpmDevice) GenKeyPair(keyID string) (b []byte, err error) {
	newKeyHandle, flush, err := tpm.keyHandler.Get(keyID)
	if err != nil {
		return nil, fmt.Errorf("cannot reseve handle for key ID %q: %w", keyID, err)
	}
	defer func() {
		flush(err == nil)
	}()
	if flog.V(5) {
		flog.Debugf("Got key handle for %q: %#x", keyID, newKeyHandle)
	}

	// First, validate we have an organization root key
	orgRootKey, err := tpm.GetOrgRootKey()
	if err != nil {
		return nil, fmt.Errorf("error while getting root key: %w", err)
	}
	defer tpm.FlushKey(orgRootKey, true)
	if flog.V(5) {
		flog.Debug("Got org root key")
	}

	// Possible shortcut: we may be asked for the org root key here.
	var newKey CryptoKey
	if newKeyHandle != orgRootKey.GetHandle() {
		newKey, err = tpm.LoadKey(keyID, orgRootKey.GetHandle(), newKeyHandle, nil)
		if err != nil {
			return nil, err
		}
		defer tpm.FlushKey(newKey, true)
		if flog.V(5) {
			flog.Debugf("Got %q key", keyID)
		}
	} else {
		newKey = orgRootKey
	}

	pubkey, err := newKey.GetECPublicKey()
	if err != nil {
		return nil, fmt.Errorf("error generating ECC key: %w", err)
	}

	return elliptic.Marshal(elliptic.P256(), pubkey.X, pubkey.Y), nil
}

func (tpm *tpmDevice) SignWithKey(keyID string, digest []byte) ([]byte, error) {
	// First get the org root key so the requested child key can be loaded and
	// used.
	orgRootKey, err := tpm.GetOrgRootKey()
	if err != nil {
		return nil, fmt.Errorf("error while getting root key: %w", err)
	}
	defer tpm.FlushKey(orgRootKey, true)

	// Next get the requested key, or bail if it can't be loaded.
	key, err := tpm.LoadKey(keyID, orgRootKey.GetHandle(), 0, nil)
	if err != nil {
		return nil, fmt.Errorf("could not load requested key %q: %w", keyID, err)
	}
	defer tpm.FlushKey(key, true)

	signature, err := tpm2.Sign(
		tpm.rwc,
		key.GetLoadedHandle(),
		"",
		digest,
		nil,
		&tpm2.SigScheme{
			Alg:  tpm2.AlgECDSA,
			Hash: tpm2.AlgSHA256,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("could not sign with key %q: %w", keyID, err)
	}

	// The standard elliptic Marshal includes more data than needed, which
	// causes signature validation problems. Create a simple struct with just
	// the EC points and marshal that in ASN.1 format.
	basicSig := utils.ECCSignature{
		R: signature.ECC.R,
		S: signature.ECC.S,
	}

	derBytes, err := asn1.Marshal(basicSig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECC signature: %w", err)
	}

	return derBytes, nil
}

func (tpm *tpmDevice) FindPubKey(keyID string) ([]byte, error) {
	// Load the stored key from disk
	key, err := tpm.LoadDiskKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("could not find key %q: %w", keyID, err)
	}
	if key == nil {
		return nil, nil
	}
	if key.IsEmpty() {
		return nil, fmt.Errorf("key is empty: %q", keyID)
	}
	defer key.Close()

	pubKey, err := key.GetECPublicKey()
	if err != nil {
		return nil, fmt.Errorf("error getting public key for key %q: %w", keyID, err)
	}

	return elliptic.Marshal(elliptic.P256(), pubKey.X, pubKey.Y), nil
}

func (tpm *tpmDevice) DeleteKey(keyID string) error {
	key, err := tpm.LoadDiskKey(keyID)
	if err != nil {
		return fmt.Errorf("error while loading key %q: %w", keyID, err)
	}

	if key == nil {
		return fmt.Errorf("key not found: %q", keyID)
	}

	flush := tpm.keyHandler.Remove(keyID)
	err = tpm.doKeyDeletion(keyID, key.GetHandle(), true)
	flush(err == nil)
	return err
}

// This allows deleting a key from the TPM. The mustExist parameter determines
// the action taken if the TPM has no key present at the given handle: if true
// an error is returned if there is no key present, if false a missing key is
// silently ignored.
func (tpm *tpmDevice) doKeyDeletion(keyID string, keyHandle tpmutil.Handle, mustExist bool) (err error) {
	// Attempt to evict the key from the TPM
	err = tpm2.EvictControl(
		tpm.rwc,
		"",
		tpm2.HandleOwner,
		keyHandle,
		keyHandle,
	)

	if err != nil && mustExist {
		return err
	}

	// Finally, delete from disk
	db, err := diskio.OpenDB()
	if err != nil {
		return err
	}

	err = db.Delete(keyID)
	if err != nil && mustExist {
		return err
	}

	return nil
}

// vim: filetype=go:noexpandtab:ts=2:sts=2:sw=2:autoindent
