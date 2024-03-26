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
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"io"

	"github.com/facebookincubator/sks/attest"
	"github.com/facebookincubator/sks/utils"
)

// This file contains all structs needed for Linux TPM usage

// Cryptoprocessor defines the interface to anything handling crypto operations
// for us. This could be a TPM, or for devices without a TPM it could be local
// storage with the crypto handled in code.
type Cryptoprocessor interface {
	// Initialize instantiates a new connection to the TPM.
	Initialize() error

	// CloseTPM shuts down a TPM session. This should always be called right
	// before the process exist. After calling `Close()`, calls to the TPM will
	// fail and you must fetch a new Cryptoprocessor instance.
	Close() error

	// FlushKey removes a key from TPM transient storage.
	FlushKey(key CryptoKey, closeKey bool) error

	// GenKeyPair generates a key pair given a label and a tag. The public key
	// is returned as X and Y in ASN.1 DER format.
	GenKeyPair(keyID string) ([]byte, error)

	// GetSecureHardwareVendorData gets vendor specific information from the secure
	// hardware implementation available for a given device
	GetSecureHardwareVendorData() (*attest.SecureHardwareVendorData, error)

	// FindPubKey looks for a key with the specified label and tag and return
	// the public key, as X and Y in ASN.1 DER format.
	FindPubKey(keyID string) ([]byte, error)

	// DeleteKey deletes a key from TPM persistent storage
	DeleteKey(keyID string) error

	// GetOrgRootKey fetches the organization root key, creating a new one if
	// needed.
	// Having the organization root key requires a primary key, but primary keys
	// cannot be stored. Fortunately, primary keys are generated using the
	// hierarchy seed, so the same template used to generate a key in the same
	// hierarchy will always generate the same key. And since we're using ECC
	// keys, generation is extremely fast.
	// This function wraps the logic of generating the primary key, loading the
	// organization root key if it exists (generating it if not) and returning
	// the organization root key.
	// NOTE: The organization root key will be loaded into the TPM ready for
	// use. This handle IS NOT FLUSHED AUTOMATICALLY! It is the responsibility
	// of the caller to flush the handle as early as possible.
	GetOrgRootKey() (CryptoKey, error)

	// GenerateKey generates a key in the TPM. Set persistentHandle to 0 if you
	// don't want the key persisted (it will not be evicted to persistent TPM
	// storage and the handle won't be recorded anywhere). keyID is ignored if
	// persistentHandle is 0. When parent is a hierarchy, both keyID and
	// persistentHandle are ignored. If you want to use the default template
	// (see templates.go; DefaultECCEKTemplate for the primary key and
	// DefaultECCKeyTemplate for other keys) set template to nil, or pass the
	// template to use.
	GenerateKey(parent tpmutil.Handle, keyID string, persistentHandle tpmutil.Handle, template *tpm2.Public) (CryptoKey, error)

	// LoadKey loads the key with the specified keyID, generating it if it
	// doesn't exist. The key will be loaded into the TPM ready to use. Set
	// persistentHandle to the handle the key should be persisted to if it
	// doesn't exist, and parentHandle to the parent to generate the key under
	// if it doesn't exist. To specify a specific template to use when
	// generating keys, use the template parameter. If set to nil, the default
	// key template will be used.
	// NOTE: Handles ARE NOT FLUSHED AUTOMATICALLY! It is the caller's
	// responsibility to flush these handles as early as possible.
	LoadKey(keyID string, parentHandle, persistentHandle tpmutil.Handle, template *tpm2.Public) (CryptoKey, error)

	// LoadDiskKey unmarshals a key from disk storage and returns it. An error is
	// returned for error conditions. Running a TPM simulator or not finding a key
	// in the database are not error conditions, callers should interpret a nil key
	// and error as a signal to generate a new key.
	LoadDiskKey(keyID string) (CryptoKey, error)

	// SignWithKey gets the key with the specified keyID and tag and signs the
	// provided data with it. The caller is expected to have hashed the data
	// and pass the digest here. The signature is returned in ASN.1 DER format
	// with only the R and S values.
	SignWithKey(keyID string, digest []byte) ([]byte, error)

	// AttestKey performs a TPM 2.0 handshake and attests the provided TPM key
	AttestKey(keyID string, attestor attest.Attestor) (*attest.Resp, error)
}

// CryptoKey defines the interface any representation of a key to be used with
// the TPM must implement.
type CryptoKey interface {
	// GetHandle returns the handle to the key in the TPM.
	GetHandle() tpmutil.Handle

	// GetLoadedHandle returns the handle to the key in the TPM when loaded.
	// This differs from GetHandle; GetHandle is for the persistent handle of
	// the key in the TPM, GetLoadedHandle is for the handle where the key may
	// actually be used and may be 0 if the key is not loaded for use.
	GetLoadedHandle() tpmutil.Handle

	// SetLoadedHandle provides a way to set the TPM handle the key is currently
	// loaded at. Set to 0 to indicate the key is not loaded.
	SetLoadedHandle(handle tpmutil.Handle)

	// Close empties a key's fields to make it invalid for future use.
	Close() error

	// IsEmpty determines if a TPMKey is empty (has no usable key data).
	// Currently this only means the public area is empty.
	IsEmpty() bool

	// GetECPublicKey extracts the ECC public key parameters from the key's
	// public area and returns it to you. If this is not an ECC key, this
	// will return an error.
	GetECPublicKey() (*utils.ECCPublicKey, error)

	// GetPublicArea returns the key's public area.
	GetPublicArea() tpm2.Public

	// GetPublicBytes returns the raw bytes of the key's public area.
	// This may return nil if an error occurs.
	GetPublicBytes() []byte

	// GetPrivateArea returns the key's private area. This is not guaranteed to
	// be available, in which case the returned tpm2.Private struct will be
	// empty.
	GetPrivateArea() tpm2.Private

	// GetPrivateBytes returns the raw bytes of the key's private area. This is
	// not guaranteed to be available.
	GetPrivateBytes() []byte

	// FillKeyData provides a way to fill in key data not directly filled in
	// when a key is generated.
	FillKeyData(publicBytes, privateBytes, creationData, keyName []byte) error
}

// tpmDevice is the opaque struct interfacing with the TPM device on Linux. This will
// be an implementation of the Cryptoprocessor interface.
type tpmDevice struct {
	// This is the interface with the TPM device/simulator
	rwc io.ReadWriteCloser

	keyHandler KeyHandler

	// This is the path to the TPM device in use.
	path string
}

// tpmKey is the opaque struct representing a key loaded from the TPM. This will
// be an implementation of the CryptoKey interface.
type tpmKey struct {
	// PublicArea is the public area of a TPM key. This must always be present.
	PublicArea tpm2.Public

	// PublicBytes is the raw public bytes returned from the TPM.
	PublicBytes []byte

	// PrivateArea is the private area of a TPM key. This is not guaranteed to
	// be available.
	PrivateArea tpm2.Private

	// PrivateBytes is the raw private bytes returned from the TPM. This is not
	// guaranteed to be available.
	PrivateBytes []byte

	// Name is the TPM's representation of a "key name", which is either a
	// TPM handle or a digest.
	Name tpm2.Name

	// Ticket is the TPM ticket, which is evidence the TPM previously processed
	// information.
	Ticket tpm2.Ticket

	// CreationData is the TPM creation data, encoding attributes and
	// environment for an object created on the TPM.
	CreationData *tpm2.CreationData

	// CreationHash is the creation data hash
	CreationHash []byte

	// Handle is the TPM handle for the key
	Handle tpmutil.Handle

	// This is the handle the key is currently loaded at. This may differ from
	// Handle and should be used when operating on a key loaded in the TPM.
	loadedHandle tpmutil.Handle

	// Parent is the parent key of this key. This is unset for a primary key.
	Parent tpmutil.Handle
}

// attestTPMCommandChannel is the opaque struct interfacing the attest.CommandChannelTPM20
// and provides the underlying tpmDevice handle as the readWriteCloser.
type attestTPMCommandChannel struct {
	io.ReadWriteCloser
}
