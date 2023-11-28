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

// This file contains functions for a cryptographic processor (such as a TPM)

import (
	"errors"
	"fmt"
	"os"

	"github.com/facebookincubator/sks/diskio"
	"github.com/facebookincubator/sks/utils"

	"github.com/facebookincubator/flog"
	attestUtils "github.com/facebookincubator/sks/attest"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// GetCryptoprocessor handles the logic of determining whether to use a physical
// TPM, on-disk implementation, or software implementation. Set `path` to the absolute path of the TPM
// device or the unix socket to interface with. Unless you have a good reason, this should be set
// to `/dev/tpmrm0`.
func GetCryptoprocessor(path string) (Cryptoprocessor, error) {
	// Check if the TPM path exists
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	var tpm Cryptoprocessor
	if (os.ModeDevice|os.ModeCharDevice|os.ModeSocket)&info.Mode() != 0 {
		tpm = &tpmDevice{
			path: path,
		}
	} else {
		return nil, fmt.Errorf(
			"path %q is not a character device, only TPMs are supported",
			path,
		)
	}

	return tpm, nil
}

func (tpm *tpmDevice) GetSecureHardwareVendorData() (*attestUtils.SecureHardwareVendorData, error) {
	if tpm.rwc == nil {
		return nil, errors.New("TPM session has been already closed")
	}

	attestConfig := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
		CommandChannel: &attestTPMCommandChannel{
			tpm.rwc,
		},
	}

	attestHandle, err := attest.OpenTPM(attestConfig)
	if err != nil {
		return nil, err
	}

	info, err := attestHandle.Info()
	if err != nil {
		return nil, err
	}

	eks, err := attestHandle.EKs()
	if err != nil {
		return nil, err
	}

	var ekList []attestUtils.EKData
	for _, ek := range eks {
		var ekData attestUtils.EKData
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
			ekData.CertDownloadedFromVendorURL = false
			ekData.VendorCertificateURL = ek.CertificateURL
			ekData.PublicKeyAlgorithm = utils.GetPubKeyType(ek.Public)
		}
		ekList = append(ekList, ekData)
	}

	return &attestUtils.SecureHardwareVendorData{
		EKs:                    ekList,
		IsTPM20CompliantDevice: true,
		VendorName:             info.Manufacturer.String(),
		VendorInfo:             info.VendorInfo,
		Version:                uint8(info.Version),
	}, nil
}

func (tpm *tpmDevice) Initialize() error {
	if tpm == nil {
		return errors.New("cannot insnantiate a nil instance")
	}

	rwc, err := tpm2.OpenTPM(tpm.path)
	if err != nil {
		return err
	}

	tpm.rwc = rwc

	flog.Debugf("Loaded TPM device: %s", tpm.path)

	db, err := diskio.OpenDB()
	if err != nil {
		return err
	}
	handles := make(map[string]tpmutil.Handle)
	err = db.Visit(func(key string, val []byte) error {
		var keyobj tpmKey
		if err := utils.UnmarshalBytes(val, &keyobj); err != nil {
			flog.Criticalf("Failed to unmarshal key %q: %+v", key, err)
			return err
		}
		handles[key] = keyobj.Handle
		flog.Debugf("Found handle for key %q: %#x", key, keyobj.Handle)
		return nil
	})

	if err != nil {
		flog.Criticalf("Failed to init key handler: %+v", err)
		return err
	}

	tpm.keyHandler = NewKeyHandler(handles)

	flog.Debugf("Initialized key handler")

	return nil
}

func (tpm *tpmDevice) Close() error {
	if tpm == nil || tpm.rwc == nil {
		return errors.New("TPM session is already closed")
	}

	tpm.rwc.Close()

	tpm.rwc = nil
	tpm.path = ""

	tpm = nil

	return nil
}

func (tpm *tpmDevice) FlushKey(key CryptoKey, closeKey bool) error {
	err := tpm2.FlushContext(tpm.rwc, key.GetLoadedHandle())
	if err != nil {
		return err
	}

	if closeKey {
		err = key.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (tpm *tpmDevice) GenerateKey(parent tpmutil.Handle, keyID string, persistentHandle tpmutil.Handle, template *tpm2.Public) (CryptoKey, error) {
	db, err := diskio.OpenDB()
	if err != nil {
		return nil, err
	}

	key := &tpmKey{}

	if parent == tpm2.HandleEndorsement || parent == tpm2.HandleOwner ||
		parent == tpm2.HandleNull {

		flog.Debugf("Generating a primary key under hierarchy 0x%x", parent)

		// Yes, the canonical Golang way is to use short assignment. But that
		// blocks directly using the existing fields in the TPMKey struct. Go
		// complain to https://github.com/golang/go/issues/30318
		var publicArea []byte
		var creationData []byte
		var keyName []byte
		var err error
		key.Handle, publicArea, creationData, key.CreationHash, key.Ticket, keyName, err = tpm2.CreatePrimaryEx(
			tpm.rwc,
			parent,
			// We are not sealing this key to any PCR state
			tpm2.PCRSelection{},
			"",
			"",
			// Changing this template will change the primary key that gets
			// generated. Modify this at your peril.
			DefaultECCEKTemplate(),
		)
		if err != nil {
			flog.Debugf("Error in CreatePrimaryEx: %+v", err)
			return nil, err
		}

		err = key.FillKeyData(publicArea, nil, creationData, keyName)
		if err != nil {
			return nil, err
		}

		flog.Debugf("Generated primary key at handle 0x%x", key.Handle)

		return key, nil
	}

	flog.Debugf("Generating new key under parent handle 0x%x", parent)

	var keyTmpl tpm2.Public
	if template == nil {
		keyTmpl = DefaultECCKeyTemplate()
	} else {
		keyTmpl = *template
	}
	flog.Debugf("Using template: %+v", keyTmpl)
	privateBlob, publicBlob, _, _, _, err := tpm2.CreateKey(
		tpm.rwc,
		parent,
		// We are not sealing this key to any PCR state
		tpm2.PCRSelection{},
		"",
		"",
		keyTmpl,
	)
	if err != nil {
		flog.Criticalf("Error generating SRK: %+v", err)
		return nil, err
	}
	flog.Debug("Created new key")

	err = key.FillKeyData(publicBlob, privateBlob, nil, nil)
	if err != nil {
		return nil, err
	}
	key.Parent = parent

	if persistentHandle > 0 {
		// Need to load the key, then evict it, and unload it when we're done
		loadedHandle, _, err := tpm2.Load(
			tpm.rwc,
			parent,
			"",
			publicBlob,
			privateBlob,
		)
		if err != nil {
			flog.Criticalf("Failed to load new key: %+v", err)
			return nil, err
		}
		defer tpm2.FlushContext(tpm.rwc, loadedHandle)
		flog.Debugf("Loaded new key at handle 0x%x", loadedHandle)

		// Attempt to remove the key stored at persistentHandle, in case one
		// already exists in the TPM and/or disk cache.
		err = tpm.doKeyDeletion(keyID, persistentHandle, false)
		if err != nil {
			flog.Errorf(
				"Failed deleting key at NV index 0x%x: %+v",
				persistentHandle,
				err,
			)
		}

		err = tpm2.EvictControl(
			tpm.rwc,
			"",
			// You may note elsewhere we state we want only the endorsement
			// hierarchy because it's privacy-sensitive, but here we use Owner.
			// Owner isn't a hierarchy, it's an authorization handle, but the
			// go-tpm library doesn't distinguish between handle types in the
			// variable names.
			tpm2.HandleOwner,
			loadedHandle,
			persistentHandle,
		)
		if err != nil {
			flog.Criticalf(
				"Failed to evict new key to persistent storage: %+v", err)
			return nil, err
		}
		key.Handle = persistentHandle
		flog.Debugf("Key persisted to storage at handle 0x%x", persistentHandle)

		// Now save the key so we can use it later, needed for loading the key
		// into the TPM once it's been flushed.S
		keyBytes, err := utils.MarshalBytes(key)
		if err != nil {
			flog.Criticalf("Failed to marshal key: %+v", err)
			return nil, err
		}

		_, err = db.Save(keyID, keyBytes)
		if err != nil {
			flog.Criticalf("Failed to save marshaled key to disk: %+v", err)
			return nil, err
		}
		flog.Debugf("Key marshaled with identifier %s", keyID)
	}

	return key, nil
}

func (tpm *tpmDevice) LoadKey(keyID string, parentHandle, persistentHandle tpmutil.Handle, template *tpm2.Public) (CryptoKey, error) {
	cpKey, err := tpm.LoadDiskKey(keyID)
	if err != nil {
		return nil, err
	}

	if cpKey == nil || cpKey.IsEmpty() {
		flog.Warningf("Key '%s' not found, attempting to create it", keyID)

		cpKey, err = tpm.GenerateKey(
			parentHandle, keyID, persistentHandle, template)
		if err != nil {
			return nil, err
		}
		if cpKey == nil || cpKey.IsEmpty() {
			return nil, errors.New("failed to load key: empty key found")
		}
	}

	loadedHandle, _, err := tpm2.Load(
		tpm.rwc,
		parentHandle,
		"",
		cpKey.GetPublicBytes(),
		cpKey.GetPrivateBytes(),
	)
	if err != nil {
		return nil, err
	}

	cpKey.SetLoadedHandle(loadedHandle)
	return cpKey, nil
}

func (tpm *tpmDevice) GetOrgRootKey() (CryptoKey, error) {
	// Get the organization root key
	// We explicitly only want to use the Endorsement Hierarchy, it's the only
	// privacy-sensitive hierarchy and the one explicitly recommended for use
	// when there are privacy considerations.
	primaryKey, err := tpm.GenerateKey(tpm2.HandleEndorsement, "", 0, nil)
	if err != nil {
		flog.Debugf("Error generating new primary key: %+v", err)
		return nil, err
	}
	defer tpm2.FlushContext(tpm.rwc, primaryKey.GetHandle())
	flog.Debug("Generated primary key")

	// Try to load the organization root key, create it if it doesn't exist
	rootKeyTmpl := DefaultECCEKTemplate()
	rootKey, err := tpm.LoadKey(
		diskio.OrgRootKey,
		primaryKey.GetHandle(),
		TPMOrgSRKHandle,
		&rootKeyTmpl,
	)
	if err != nil {
		flog.Criticalf("Error loading organization root key: %+v", err)
		return nil, err
	}
	flog.Debugf(
		"Found organization root key with handle 0x%x", rootKey.GetHandle())

	return rootKey, nil
}

func (tpm *tpmDevice) LoadDiskKey(keyID string) (CryptoKey, error) {
	db, err := diskio.OpenDB()
	if err != nil {
		return nil, err
	}

	keyBytes, err := db.Load(keyID)
	if err != nil {
		flog.Warningf("Got error loading key from disk: %+v", err)
		return nil, nil
	}
	if len(keyBytes) <= 0 {
		flog.Warning("Loaded key file but got no data")
		return nil, nil
	}

	flog.Debugf("Attempting to unmarshal key '%s'", keyID)

	var keyobj tpmKey
	if err := utils.UnmarshalBytes(keyBytes, &keyobj); err != nil {
		flog.Criticalf("Failed to unmarshal key '%s': %+v", keyID, err)
		return nil, err
	}

	if keyobj.IsEmpty() {
		flog.Warningf(
			"Key '%s' loaded, but has no data; generate a new key",
			keyID,
		)
		return nil, nil
	}

	keyobj.FillKeyData(keyobj.PublicBytes, nil, nil, nil)

	return &keyobj, nil
}

// vim: filetype=go:noexpandtab:ts=2:sts=2:sw=2:autoindent
