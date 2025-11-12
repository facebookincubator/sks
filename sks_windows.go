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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/facebookincubator/sks/attest"
	"github.com/facebookincubator/sks/utils"

	tpm "github.com/google/certtostore"
	goattest "github.com/google/go-attestation/attest"
)

const (
	// KeyStorageProvider is a provider used by sks.
	KeyStorageProvider = "Microsoft Platform Crypto Provider"

	// errKeyDoesNotExist is the error returned by Microsoft Crypto Provider
	// when the requested key was not found in the provider. Taken from
	// ncrypt.h.
	errKeyDoesNotExist = "80090016"
)

// UseWindowsMachineStore is a flag that can be set to true to use the machine store instead of the user store (default)
// This is applicable only to Windows.
var UseWindowsMachineStore bool

// getWindowsCertStore defaults to the current user's cert store, but can be
// overridden to use the machine cert store by setting UseWindowsMachineStore to true.
func getWindowsCertStore(label string) (*tpm.WinCertStore, error) {
	if UseWindowsMachineStore {
		return tpm.OpenWinCertStore(
			KeyStorageProvider,
			label,
			[]string{},
			[]string{},
			false,
		)
	}

	return tpm.OpenWinCertStoreCurrentUser(
		KeyStorageProvider,
		label,
		[]string{},
		[]string{},
		false,
	)
}

// genKeyPair creates a key with the given label and tag
// Returns public key raw data.
// tag, useBiometrics, and accessibleWhenUnlockedOnly are ignored
func genKeyPair(label, tag string, _, _ bool) ([]byte, error) {
	certStore, err := getWindowsCertStore(label)
	if err != nil {
		return nil, fmt.Errorf(ErrGenKeyPair, label, tag, err)
	}
	key, err := certStore.Generate(tpm.GenerateOpts{
		Algorithm: tpm.EC,
		Size:      256,
	})
	if err != nil {
		return nil, fmt.Errorf(ErrGenKeyPair, label, tag, err)
	}
	pubKey := key.Public().(*ecdsa.PublicKey)
	return elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y), nil
}

// attestKey performs a TPM 2.0 handshake using the underlying Endorsement
// key, creates a TPM Attestation key bound to the EK
// which further certifies that the TPM key represented by the provided label
// is attested & from the same TPM as the EK.
func attestKey(label, tag string, attestor attest.Attestor) (*attest.Resp, error) {
	if attestor == nil {
		return nil, fmt.Errorf(ErrAttestationFailure, label, tag, errors.New("nil attestor handle"))
	}

	cred, err := findPrivateKey(label)
	if err != nil {
		return nil, fmt.Errorf(ErrAttestationFailure, label, tag, err)
	}
	if cred == nil {
		return nil, fmt.Errorf(ErrAttestationFailure, label, tag, errors.New("nil tpm.Credential handle from PCP store"))
	}

	k, ok := cred.(*tpm.Key)
	if !ok {
		return nil, fmt.Errorf(ErrAttestationFailure, label, tag, errors.New("retrieved tpm.Credential has an invalid wrapped PCP key"))
	}

	handle := k.TransientTpmHandle()
	resp, err := attestor.Attest(&attest.Req{
		KeyHandle: handle,
	})
	if err != nil {
		return nil, fmt.Errorf(ErrAttestationFailure, label, tag, err)
	}

	return resp, nil
}

// signWithKey signs arbitrary data pointed to by data with the key described by
// label and tag. Returns the signed data.
// tag and key hash are not used.
func signWithKey(label, tag string, _, digest []byte) ([]byte, error) {
	cred, err := findPrivateKey(label)
	if err != nil {
		return nil, fmt.Errorf(ErrSignWithKey, label, tag, err)
	}
	if cred == nil {
		return nil, fmt.Errorf("failed to find key with label %q and tag %q", label, tag)
	}
	return cred.Sign(nil, digest, nil)
}

// findPubKey returns the raw public key described by label and tag
// tag and hash are not used
func findPubKey(label, tag string, hash []byte) ([]byte, error) {
	key, err := findPrivateKey(label)
	if err != nil {
		return nil, fmt.Errorf(ErrFindPubKey, label, tag, err)
	}
	// The lib API expects that we return a nil error here with a nil key
	// to signify that the key was not found.
	if key == nil {
		return nil, nil
	}
	pubKey := key.Public().(*ecdsa.PublicKey)
	return elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y), nil
}

// ncryptRemoveKey removes key from tpm storage.
// TODO: send patch to implement this method upstream.
func ncryptRemoveKey(cred tpm.Credential) error {
	key, ok := cred.(*tpm.Key)
	if !ok {
		return fmt.Errorf("unexpected key type, got %T, want *certtostore.Key", key)
	}
	nCrypt := windows.MustLoadDLL("ncrypt.dll")
	nCryptDeleteKey := nCrypt.MustFindProc("NCryptDeleteKey")
	handle := key.TransientTpmHandle()
	r, _, err := nCryptDeleteKey.Call(
		handle,
		0,
	)
	if r != 0 {
		return fmt.Errorf("NCryptDeleteKey returned %X: %v", r, err)
	}
	return nil
}

// removeKey tries to delete a key identified by label, tag and hash.
// tag and hash are not used
// Returns true if the key was found and deleted successfully
func removeKey(label, tag string, _ []byte) (bool, error) {
	cred, err := findPrivateKey(label)
	if err != nil {
		return false, fmt.Errorf(ErrRemoveKey, label, tag, err)
	}
	if cred == nil {
		return false, fmt.Errorf("failed to find key with label %q and tag %q", label, tag)
	}

	if err := ncryptRemoveKey(cred); err != nil {
		return false, fmt.Errorf(ErrRemoveKey, label, tag, err)
	}
	return true, nil
}

func findPrivateKey(label string) (tpm.Credential, error) {
	certStore, err := getWindowsCertStore(label)
	if err != nil {
		return nil, err
	}
	key, err := certStore.Key()
	if err != nil {
		// Windows will return an error with the specified content if the key was not
		// found.
		if strings.Contains(err.Error(), errKeyDoesNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return key, nil
}

func getSecureHardwareVendorData() (*attest.SecureHardwareVendorData, error) {
	attestTPMHandle, err := goattest.OpenTPM(nil)
	if err != nil {
		return nil, err
	}
	defer attestTPMHandle.Close()

	info, err := attestTPMHandle.Info()
	if err != nil {
		return nil, err
	}

	eks, err := attestTPMHandle.EKs()
	if err != nil {
		return nil, err
	}

	var ekList []attest.EKData
	for _, ek := range eks {
		var ekData attest.EKData
		if ek.Certificate != nil {
			ekData.Certificate = append(ekData.Certificate, ek.Certificate.Raw...)
			ekData.IssuerCN = ek.Certificate.Issuer.CommonName
			ekData.SubjectCN = ek.Certificate.Subject.CommonName
			ekData.SerialNumber = ek.Certificate.SerialNumber.String()
			ekData.HasCertInNVRAM = true
			ekData.HasPublicKeyInNVRam = false
			ekData.CertDownloadedFromVendorURL = false
			ekData.SignatureAlgorithm = ek.Certificate.SignatureAlgorithm.String()
			ekData.PublicKeyAlgorithm = ek.Certificate.PublicKeyAlgorithm.String()
		} else if ek.Public != nil {
			// TODO populate values similar to above once we enabled downloading of certificates
			// from the corresponding vendor's upstream EK fetcher URL
			ekData.HasCertInNVRAM = false
			ekData.HasPublicKeyInNVRam = true
			var (
				rsaKey *rsa.PublicKey
				ok     bool
			)
			if rsaKey, ok = ek.Public.(*rsa.PublicKey); !ok {
				return nil, fmt.Errorf("unsupported public key type: %T", ek.Public)
			}
			rawPubKey, err := x509.MarshalPKIXPublicKey(rsaKey)
			if err != nil {
				return nil, err
			}
			ekData.PublicKey = rawPubKey
			ekData.CertDownloadedFromVendorURL = false
			ekData.VendorCertificateURL = ek.CertificateURL
			ekData.PublicKeyAlgorithm = utils.GetPubKeyType(*rsaKey)
		}
		ekList = append(ekList, ekData)
	}

	return &attest.SecureHardwareVendorData{
		EKs:                    ekList,
		IsTPM20CompliantDevice: true,
		VendorName:             info.Manufacturer.String(),
		VendorInfo:             info.VendorInfo,
		Version:                2, // We only support tpm 2.0
	}, nil
}
