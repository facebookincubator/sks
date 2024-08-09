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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"io"

	attestIf "github.com/facebookincubator/sks/attest"
	"github.com/google/go-attestation/attest"
)

const (
	tpmHandleLabel          = "attest_tpm_handle"
	transientAkHandleLabel  = "transient_ak_handle"
	transientKeyHandleLabel = "transient_key_handle"
)

// newTransientKey creates a new transient key, which is TPM2.0 certified by an AK (attestation key)
func newTransientKey(tpm *attest.TPM, config *attest.KeyConfig) (*attest.Key, *attest.AK, error) {
	if tpm == nil {
		return nil, nil, fmt.Errorf(ErrInvalidTPMHandle, tpmHandleLabel)
	}

	ak, err := tpm.NewAK(nil)
	if err != nil {
		return nil, nil, err
	}

	key, err := tpm.NewKey(ak, config)
	if err != nil {
		return nil, nil, err
	}

	return key, ak, nil
}

// loadTransientKey loads the transient key, the transientAK Key based on the TPM 2.0 encrypted blobs
func loadTransientKey(tpm *attest.TPM, transientAKBlob, transientKeyBlob []byte) (*attest.Key, *attest.AK, error) {
	if tpm == nil {
		return nil, nil, fmt.Errorf(ErrInvalidTPMHandle, tpmHandleLabel)
	}

	if transientAKBlob == nil {
		return nil, nil, fmt.Errorf(ErrEmptyTPM20EncryptedBlob, transientAkHandleLabel)
	}

	if transientKeyBlob == nil {
		return nil, nil, fmt.Errorf(ErrEmptyTPM20EncryptedBlob, transientKeyHandleLabel)
	}

	ak, err := tpm.LoadAK(transientAKBlob)
	if err != nil {
		return nil, nil, err
	}

	key, err := tpm.LoadKey(transientKeyBlob)
	if err != nil {
		return nil, nil, err
	}

	return key, ak, nil
}

type attestkey struct {
	handle      *attest.TPM
	transient   *attest.Key
	akTransient *attest.AK
	attestor    attestIf.Attestor
	label       string
	tag         string
}

// Config is the configuration for the transient key
type Config struct {
	TransientAKKeyBlob  []byte
	TransientSKSKeyBlob []byte
	Attestor            attestIf.Attestor
}

// Option is a list of options for the transient key
type Option func(config *Config) *Config

// newConfig creates a Config for the shared CLI from a list of Options.
func newConfig(options ...Option) *Config {
	config := &Config{
		TransientAKKeyBlob:  nil,
		TransientSKSKeyBlob: nil,
	}

	for _, option := range options {
		config = option(config)
	}
	return config
}

// WithAKKeyBlob sets the AK blob for the transient key
func WithAKKeyBlob(akBlob []byte) Option {
	return func(config *Config) *Config {
		config.TransientAKKeyBlob = akBlob
		return config
	}
}

// WithSKSKeyBlob sets the SKS blob for the transient key
func WithSKSKeyBlob(sksBlob []byte) Option {
	return func(config *Config) *Config {
		config.TransientSKSKeyBlob = sksBlob
		return config
	}
}

// WithAttestor sets the attestor for the transient key
func WithAttestor(attestor attestIf.Attestor) Option {
	return func(config *Config) *Config {
		config.Attestor = attestor
		return config
	}
}

// New creates (or) loads a transient key, which is TPM2.0 certified by an AK (attestation key)
func New(label string, tag string, options ...Option) (Key, error) {
	config := newConfig(options...)
	var (
		handle      *attest.TPM
		transient   *attest.Key
		akTransient *attest.AK
		attestor    attestIf.Attestor
		err         error
	)

	handle, err = attest.OpenTPM(nil)
	if err != nil {
		return nil, err
	}

	attestor = config.Attestor
	if config.TransientAKKeyBlob == nil || config.TransientSKSKeyBlob == nil {
		transient, akTransient, err = newTransientKey(handle, nil)
		if err != nil {
			return nil, err
		}
	} else {
		transient, akTransient, err = loadTransientKey(handle, config.TransientAKKeyBlob, config.TransientSKSKeyBlob)
		if err != nil {
			return nil, err
		}
	}

	return &attestkey{
		transient:   transient,
		akTransient: akTransient,
		attestor:    attestor,
		handle:      handle,
		label:       label,
		tag:         tag}, nil
}

func (k *attestkey) Public() crypto.PublicKey {
	return k.transient.Public()
}

func (k *attestkey) Attest() error {
	_, err := k.attestor.Attest(&attestIf.Req{
		AttestTPMHandle:    k.handle,
		TransientAKHandle:  k.akTransient,
		TransientKeyHandle: k.transient,
	})
	if err != nil {
		return fmt.Errorf("attestation failure: %w", err)
	}
	return nil
}

func (k *attestkey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	pkey, err := k.transient.Private(k.transient.Public())
	if err != nil {
		return nil, err
	}

	signer, ok := pkey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf(ErrInvalidCryptoSigner)
	}

	return signer.Sign(rand, digest, opts)
}

// Hash returns the hash of the public key
func (k *attestkey) Hash() []byte {
	pubkey, ok := k.transient.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil
	}

	rawKey := elliptic.Marshal(pubkey.Curve, pubkey.X, pubkey.Y)
	h := sha256.Sum256(rawKey)
	return h[:]
}

// Label returns the label of the key
func (k *attestkey) Label() string {
	return k.label
}

// Tag returns the tag of the key
func (k *attestkey) Tag() string {
	return k.tag
}

// Remote returns an error as key creation is handled outside of this library
func (k *attestkey) Remove() error {
	// not supported as key creation is handled outside of this library
	return fmt.Errorf(ErrNotSupported)
}

// Close closes the transient key, the transient AK and the TPM attestation handle
func (k *attestkey) Close() error {
	if k.transient != nil {
		k.transient.Close()
	}

	if k.akTransient != nil {
		k.akTransient.Close(k.handle)
	}

	if k.handle != nil {
		k.handle.Close()
	}
	return nil
}

// EncryptedBlob returns the blobs of the transient key and transient AK
func (k *attestkey) EncryptedBlob() ([]byte, []byte, error) {
	akBlob, err := k.akTransient.Marshal()
	if err != nil {
		return nil, nil, err
	}

	keyBlob, err := k.transient.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return akBlob, keyBlob, nil
}
