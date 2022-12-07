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
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"

	"github.com/facebookincubator/sks/attest"
	"github.com/facebookincubator/sks/utils"

	tpm "github.com/aimeemikaelac/certtostore"
	goattest "github.com/google/go-attestation/attest"
)

const (
	keyStorageProvider = "Microsoft Platform Crypto Provider"

	// keyDoesNotExistErr is the error returned by Microsoft Crypto Provider
	// when the requested key was not found in the provider. Taken from
	// ncrypt.h.
	errKeyDoesNotExist = "80090016"
)

// genKeyPair creates a key with the given label and tag
// Returns public key raw data.
// tag, useBiometrics, and accessibleWhenUnlockedOnly are ignored
func genKeyPair(label, tag string, _, _ bool) ([]byte, error) {
	certStore, err := tpm.OpenWinCertStore(
		keyStorageProvider,
		label,
		[]string{},
		[]string{},
	)
	if err != nil {
		return nil, fmt.Errorf(ErrGenKeyPair, label, tag, err)
	}
	key, err := certStore.Generate(256, "ECDSA_P256")
	if err != nil {
		return nil, fmt.Errorf(ErrGenKeyPair, label, tag, err)
	}
	pubKey := key.Public().(*ecdsa.PublicKey)
	return elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y), nil
}

// signWithKey signs arbitrary data pointed to by data with the key described by
// label and tag. Returns the signed data.
// tag and key hash are not used.
func signWithKey(label, tag string, _, digest []byte) ([]byte, error) {
	key, err := findPrivateKey(label)
	if err != nil {
		return nil, fmt.Errorf(ErrSignWithKey, label, tag, err)
	}
	if key == nil {
		return nil, fmt.Errorf("failed to find key with label %q and tag %q", label, tag)
	}
	key = key.(*tpm.EcdsaKey)
	sig, err := key.SignRaw(digest)
	if err != nil {
		return nil, fmt.Errorf(ErrSignWithKey, label, tag, err)
	}
	// https://stackoverflow.com/questions/38702169/c-sharp-ecdsacng-signdata-use-signature-in-openssl
	// windows encodes an ecdsa signature as concatenating r and s in the array.
	// the output sig will always be of even length
	r := new(big.Int).SetBytes(sig[0 : len(sig)/2])
	s := new(big.Int).SetBytes(sig[len(sig)/2:])
	// https://golang.org/src/crypto/ecdsa/ecdsa.go?s=2196:2295#L65
	sig, err = asn1.Marshal(utils.ECCSignature{r, s})
	if err != nil {
		return nil, fmt.Errorf(ErrSignWithKey, label, tag, err)
	}
	return sig, nil
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

// removeKey tries to delete a key identified by label, tag and hash.
// tag and hash are not used
// Returns true if the key was found and deleted successfully
func removeKey(label, tag string, _ []byte) (bool, error) {
	key, err := findPrivateKey(label)
	if err != nil {
		return false, fmt.Errorf(ErrRemoveKey, label, tag, err)
	}
	if key == nil {
		return false, fmt.Errorf("failed to find key with label %q and tag %q", label, tag)
	}
	err = key.Delete()
	if err != nil {
		return false, fmt.Errorf(ErrRemoveKey, label, tag, err)
	}
	return true, nil
}

func findPrivateKey(label string) (tpm.Key, error) {
	certStore, err := tpm.OpenWinCertStore(
		keyStorageProvider,
		label,
		[]string{},
		[]string{},
	)
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

func accessibleWhenUnlockedOnly(label, tag string, hash []byte) (bool, error) {
	return false, nil
}

func updateKeyLabel(label, tag, newLabel string, hash []byte) error {
	return fmt.Errorf(ErrNotImplemented, "updateKeyLabel")
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
			ekData.CertDownloadedFromVendorURL = false
			ekData.VendorCertificateURL = ek.CertificateURL
			ekData.PublicKeyAlgorithm = utils.GetPubKeyType(ek.Public)
		}
		ekList = append(ekList, ekData)
	}

	return &attest.SecureHardwareVendorData{
		EKs:                    ekList,
		IsTPM20CompliantDevice: true,
		VendorName:             info.Manufacturer.String(),
		VendorInfo:             info.VendorInfo,
		Version:                uint8(info.Version),
	}, nil
}
