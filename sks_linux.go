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

	"security/sks/linux"
)

// getCryptoProcessor is a wrapper that returns an initialized
// Cryptoprocessor.
func getCryptoProcessor() (linux.Cryptoprocessor, error) {
	tpm, err := linux.GetCryptoprocessor("/dev/tpmrm0")
	if err != nil {
		return nil, err
	}
	err = tpm.Initialize()
	if err != nil {
		return nil, err
	}

	return tpm, nil
}

// genKeyPair creates a key with the given label and tag
// Returns public key raw data.
// tag, useBiometrics, and accessibleWhenUnlockedOnly are ignored
func genKeyPair(label, tag string, _, _ bool) ([]byte, error) {
	tpm, err := getCryptoProcessor()
	if err != nil {
		return nil, fmt.Errorf(ErrGenKeyPair, label, tag, err)
	}
	defer tpm.Close()

	res, err := tpm.GenKeyPair(label)
	if err != nil {
		return nil, fmt.Errorf(ErrGenKeyPair, label, tag, err)
	}

	return res, nil
}

// signWithKey signs arbitrary data pointed to by data with the key described by
// label and tag. Returns the signed data.
// tag and hash are not used.
func signWithKey(label, tag string, _, data []byte) ([]byte, error) {
	tpm, err := getCryptoProcessor()
	if err != nil {
		return nil, fmt.Errorf(ErrSignWithKey, label, tag, err)
	}
	defer tpm.Close()

	res, err := tpm.SignWithKey(label, data)
	if err != nil {
		return nil, fmt.Errorf(ErrSignWithKey, label, tag, err)
	}

	return res, nil
}

// findPubKey returns the raw public key described by label and tag
// tag and hash are not used
func findPubKey(label, tag string, _ []byte) ([]byte, error) {
	tpm, err := getCryptoProcessor()
	if err != nil {
		return nil, fmt.Errorf(ErrFindPubKey, label, tag, err)
	}
	defer tpm.Close()

	res, err := tpm.FindPubKey(label)
	if err != nil {
		return nil, fmt.Errorf(ErrFindPubKey, label, tag, err)
	}

	return res, nil
}

// removeKey tries to delete a key identified by label, tag and hash.
// tag and hash are not used
// Returns true if the key was found and deleted successfully
func removeKey(label, tag string, _ []byte) (bool, error) {
	tpm, err := getCryptoProcessor()
	if err != nil {
		return false, fmt.Errorf(ErrRemoveKey, label, tag, err)
	}
	defer tpm.Close()

	err = tpm.DeleteKey(label)
	if err != nil {
		return false, fmt.Errorf(ErrRemoveKey, label, tag, err)
	}

	return true, nil
}

func accessibleWhenUnlockedOnly(label, tag string, hash []byte) (bool, error) {
	return false, nil
}

func updateKeyLabel(label, tag, newLabel string, hash []byte) error {
	return fmt.Errorf(ErrNotImplemented, "updateKeyLabel")
}
