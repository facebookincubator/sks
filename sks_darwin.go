// Package sks implements the Secure Key Store for Go

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

package sks

import (
	"fmt"

	"github.com/facebookincubator/sks/macos"
)

// genKeyPair creates a key with the given label and tag potentially
// needing biometric authentication. Returns public key raw data.
func genKeyPair(label, tag string, useBiometrics, accessibleWhenUnlockedOnly bool) ([]byte, error) {
	res, err := macos.GenKeyPair(label, tag, useBiometrics, accessibleWhenUnlockedOnly)
	if err != nil {
		return nil, fmt.Errorf(ErrGenKeyPair, label, tag, err)
	}

	return res, nil
}

// signWithKey signs arbitrary data pointed to by data with the key described by
// label and tag. Returns the signed data.
// hash is the SHA1 of the key. Can be nil
func signWithKey(label, tag string, hash, data []byte) ([]byte, error) {
	res, err := macos.SignWithKey(label, tag, hash, data)
	if err != nil {
		return nil, fmt.Errorf(ErrSignWithKey, label, tag, err)
	}

	return res, nil
}

// findPubKey returns the raw public key described by label and tag
// hash is the SHA1 of the key. Can be nil
func findPubKey(label, tag string, hash []byte) ([]byte, error) {
	res, err := macos.FindPubKey(label, tag, hash)
	if err != nil {
		return nil, fmt.Errorf(ErrFindPubKey, label, tag, err)
	}

	return res, nil
}

// removeKey tries to delete a key identified by label, tag and hash.
// hash is the SHA1 of the key. Can be nil
// If hash is nil then all the keys that match the label and tag specified will
// be deleted.
// Returns true if the key was found and deleted successfully
func removeKey(label, tag string, hash []byte) (bool, error) {
	res, err := macos.RemoveKey(label, tag, hash)
	if err != nil {
		return false, fmt.Errorf(ErrRemoveKey, label, tag, err)
	}

	return res, nil
}

// accessibleWhenUnlockedOnly checks whether or not the protection level for
// a key (identified by label, tag, and hash) is set to only accessible
// when the device is unlocked.
// hash is the SHA1 of the key. Can be nil
// Returns true if protection is set to accessible when unlocked only.
// False otherwise.
func accessibleWhenUnlockedOnly(label, tag string, hash []byte) (bool, error) {
	res, err := macos.AccessibleWhenUnlockedOnly(label, tag, hash)
	if err != nil {
		return false, fmt.Errorf(ErrAttributeLookup, label, tag, err)
	}

	return res, nil
}

// updateKeyLabel tries to update a key identified by label, tag and hash
// to a new label.
// hash is the SHA1 of the key. Can be nil
// Returns an error if the key could not be re-labeled.
func updateKeyLabel(label, tag, newLabel string, hash []byte) error {
	if err := macos.UpdateKeyLabel(label, tag, newLabel, hash); err != nil {
		return fmt.Errorf(ErrUpdateKeyAttr, label, tag, err)
	}

	return nil
}
