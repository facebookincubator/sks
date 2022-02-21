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
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Key is an interface that implements the crypto.Signer interface along with
// extra functions specific to SKS
type Key interface {
	crypto.Signer

	// Remove removes that key from SKS
	Remove() error

	// Hash returns the SHA1 hash of the public portion of the key
	Hash() []byte

	// Label returns the label of the key
	Label() string

	// Tag returns the tag of the key
	Tag() string

	// UpdateLabel changes the key's label to a new one
	UpdateLabel(newLabel string) error

	// AccessibleWhenUnlockedOnly returns whether or not the key is only
	// accessible when the device is unlocked
	AccessibleWhenUnlockedOnly() (bool, error)
}

// regularKey is an ECDSA P-256 key whose private portion is stored in SKS
type regularKey struct {
	pubKey *ecdsa.PublicKey
	label  string
	tag    string
}

// LoadKey returns an existing key backed by SKS given the corresponding label, tag, and hash
func LoadKey(label, tag string, hash []byte) (Key, error) {
	if pubKey, err := findPubKey(label, tag, hash); err != nil {
		return nil, err
	} else if pubKey != nil {
		return &regularKey{
			pubKey: rawToEcdsa(pubKey),
			label:  label,
			tag:    tag,
		}, nil
	}

	return nil, fmt.Errorf(ErrFindPubKeyNil, label, tag)
}

// NewKey returns a new key backed by SKS given the corresponding label and tag
// useBiometrics and accessibleWhenUnlockedOnly are not taken into account if the key already exist
func NewKey(label, tag string, useBiometrics, accessibleWhenUnlockedOnly bool, hash []byte) (Key, error) {
	if pubKey, err := findPubKey(label, tag, hash); err != nil {
		return nil, err
	} else if pubKey != nil {
		return &regularKey{
			pubKey: rawToEcdsa(pubKey),
			label:  label,
			tag:    tag,
		}, nil
	}

	pubKey, err := genKeyPair(label, tag, useBiometrics, accessibleWhenUnlockedOnly)
	if err != nil {
		return nil, err
	}
	return &regularKey{
		pubKey: rawToEcdsa(pubKey),
		label:  label,
		tag:    tag,
	}, nil
}

// Remove removes the key from the SKS
func (k *regularKey) Remove() error {
	if k.label == "" || k.tag == "" {
		return errors.New(ErrLabelOrTagUnspecified)
	}
	_, err := removeKey(k.label, k.tag, k.Hash())
	return err
}

// Public returns the public key of this key
func (k *regularKey) Public() crypto.PublicKey {
	if k.pubKey != nil {
		return k.pubKey
	}

	pubKey, err := findPubKey(k.label, k.tag, nil)
	if err != nil {
		return nil
	}

	if pubKey == nil {
		return nil
	}

	return rawToEcdsa(pubKey)
}

// Sign signs the arbitrary data in digest with the key
// The first argument `rand` is discarded in favour of the internal implementation
func (k *regularKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return signWithKey(k.label, k.tag, k.Hash(), digest)
}

// HashKey returns the SHA1 hash of the key
func (k *regularKey) Hash() []byte {
	if k.pubKey == nil {
		return nil
	}
	rawKey := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)
	h := sha1.Sum(rawKey)
	return h[:]
}

// Label returns the label of the key
func (k *regularKey) Label() string {
	return k.label
}

// Tag returns the tag of the key
func (k *regularKey) Tag() string {
	return k.tag
}

// AccessibleWhenUnlockedOnly returns whether or not the key is only
// accessible when the device is unlocked
func (k *regularKey) AccessibleWhenUnlockedOnly() (bool, error) {
	return accessibleWhenUnlockedOnly(k.label, k.tag, k.Hash())
}

// UpdateLabel changes the key's label to a new one.
func (k *regularKey) UpdateLabel(newLabel string) error {
	err := updateKeyLabel(k.label, k.tag, newLabel, k.Hash())
	if err == nil {
		k.label = newLabel
	}
	return err
}

// FromLabelTag constructs a Key identified by label and tag
// without looking up the key in SKS so the public key of the
// structure is not populated.
func FromLabelTag(labelTag string) Key {
	f := strings.SplitN(labelTag, ":", 2)
	k := &regularKey{
		label: f[0],
	}
	if len(f) > 1 {
		k.tag = f[1]
	}
	return k
}

// rawToEcdsa turns an ASN.1 encoded byte stream to an ecdsa public key
// It is assumed that the curve of the key is P-256
func rawToEcdsa(raw []byte) *ecdsa.PublicKey {
	ecKey := new(ecdsa.PublicKey)
	ecKey.Curve = elliptic.P256()
	ecKey.X, ecKey.Y = elliptic.Unmarshal(ecKey.Curve, raw)
	return ecKey
}
