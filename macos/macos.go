//go:build darwin
// +build darwin

// Copyright (c) Meta, Inc. and its affiliates.
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

package macos

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

const (
	nilSecKey       C.SecKeyRef       = 0
	nilCFData       C.CFDataRef       = 0
	nilCFString     C.CFStringRef     = 0
	nilCFDictionary C.CFDictionaryRef = 0
	nilCFError      C.CFErrorRef      = 0
)

// GenKeyPair creates a key with the given label and tag.
// useBiometrics and accessibleWhenUnlockedOnly are ignored,
// they are present for API compatibility.
// Returns public key raw data.
func GenKeyPair(label, tag string, useBiometrics, accessibleWhenUnlockedOnly bool) ([]byte, error) {
	protection := C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
	flags := C.kSecAccessControlPrivateKeyUsage

	cfTag, err := newCFData([]byte(tag))
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfTag))

	cfLabel, err := newCFString(label)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfLabel))

	var eref C.CFErrorRef
	access := C.SecAccessControlCreateWithFlags(
		C.kCFAllocatorDefault,
		C.CFTypeRef(protection),
		C.SecAccessControlCreateFlags(flags),
		&eref)

	if err := goError(eref); err != nil {
		C.CFRelease(C.CFTypeRef(eref))
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(access))

	privKeyAttrs, err := newCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecAttrAccessControl):  C.CFTypeRef(access),
		C.CFTypeRef(C.kSecAttrApplicationTag): C.CFTypeRef(cfTag),
		C.CFTypeRef(C.kSecAttrIsPermanent):    C.CFTypeRef(C.kCFBooleanTrue),
	})
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(privKeyAttrs))

	attrs, err := newCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecAttrLabel):       C.CFTypeRef(cfLabel),
		C.CFTypeRef(C.kSecAttrTokenID):     C.CFTypeRef(C.kSecAttrTokenIDSecureEnclave),
		C.CFTypeRef(C.kSecAttrKeyType):     C.CFTypeRef(C.kSecAttrKeyTypeEC),
		C.CFTypeRef(C.kSecPrivateKeyAttrs): C.CFTypeRef(privKeyAttrs),
	})
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(attrs))

	privKey := C.SecKeyCreateRandomKey(attrs, &eref)
	if err := goError(eref); err != nil {
		C.CFRelease(C.CFTypeRef(eref))
		return nil, err
	}
	if privKey == nilSecKey {
		return nil, fmt.Errorf("error generating random private key")
	}
	defer C.CFRelease(C.CFTypeRef(privKey))

	publicKey := C.SecKeyCopyPublicKey(privKey)
	if publicKey == nilSecKey {
		return nil, fmt.Errorf("error extracting public key")
	}
	defer C.CFRelease(C.CFTypeRef(publicKey))

	keyAttrs := C.SecKeyCopyAttributes(publicKey)
	defer C.CFRelease(C.CFTypeRef(keyAttrs))

	publicKeyData := C.CFDataRef(C.CFDictionaryGetValue(keyAttrs, unsafe.Pointer(C.kSecValueData)))
	defer C.CFRelease(C.CFTypeRef(publicKeyData))

	return C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(publicKeyData)),
		C.int(C.CFDataGetLength(publicKeyData)),
	), nil
}

// FindPubKey returns the raw public key described by label and tag
// hash is the SHA1 of the key. Can be nil.
func FindPubKey(label, tag string, hash []byte) ([]byte, error) {
	key, err := fetchSEPrivKey(label, tag, hash)
	if err == nil {
		defer C.CFRelease(C.CFTypeRef(key))
		return extractPubKey(key)
	}

	var oserr osStatusError
	if errors.As(err, &oserr) {
		if oserr.code == C.errSecItemNotFound {
			return nil, nil
		}
	}
	return nil, err
}

// SignWithKey signs arbitrary data pointed to by data with the key described by
// label and tag. Returns the signed data.
// hash is the SHA1 of the key. Can be nil.
func SignWithKey(label, tag string, hash, digest []byte) ([]byte, error) {
	key, err := fetchSEPrivKey(label, tag, hash)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(key))

	cfDigest, err := newCFData(digest)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfDigest))

	var eref C.CFErrorRef
	signature := C.SecKeyCreateSignature(key, C.kSecKeyAlgorithmECDSASignatureDigestX962, cfDigest, &eref)
	if err := goError(eref); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(signature))

	return C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(signature)),
		C.int(C.CFDataGetLength(signature)),
	), nil
}

func fetchSEPrivKey(label, tag string, hash []byte) (C.SecKeyRef, error) {
	cfTag, err := newCFData([]byte(tag))
	if err != nil {
		return nilSecKey, err
	}
	defer C.CFRelease(C.CFTypeRef(cfTag))

	cfLabel, err := newCFString(label)
	if err != nil {
		return nilSecKey, err
	}
	defer C.CFRelease(C.CFTypeRef(cfLabel))

	m := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):              C.CFTypeRef(C.kSecClassKey),
		C.CFTypeRef(C.kSecAttrKeyType):        C.CFTypeRef(C.kSecAttrKeyTypeEC),
		C.CFTypeRef(C.kSecAttrApplicationTag): C.CFTypeRef(cfTag),
		C.CFTypeRef(C.kSecAttrLabel):          C.CFTypeRef(cfLabel),
		C.CFTypeRef(C.kSecAttrKeyClass):       C.CFTypeRef(C.kSecAttrKeyClassPrivate),
		C.CFTypeRef(C.kSecReturnRef):          C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit):         C.CFTypeRef(C.kSecMatchLimitOne),
	}

	if hash != nil {
		d, err := newCFData(hash)
		if err != nil {
			return nilSecKey, err
		}
		defer C.CFRelease(C.CFTypeRef(d))

		m[C.CFTypeRef(C.kSecAttrApplicationLabel)] = C.CFTypeRef(d)
	}

	query, err := newCFDictionary(m)
	if err != nil {
		return nilSecKey, err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var key C.CFTypeRef
	status := C.SecItemCopyMatching(query, &key)
	if err := goError(status); err != nil {
		return nilSecKey, err
	}

	return C.SecKeyRef(key), nil
}

func extractPubKey(key C.SecKeyRef) ([]byte, error) {
	publicKey := C.SecKeyCopyPublicKey(key)
	defer C.CFRelease(C.CFTypeRef(publicKey))

	keyAttrs := C.SecKeyCopyAttributes(publicKey)
	defer C.CFRelease(C.CFTypeRef(keyAttrs))

	val := C.CFDataRef(C.CFDictionaryGetValue(keyAttrs, unsafe.Pointer(C.kSecValueData)))
	if val == nilCFData {
		return nil, fmt.Errorf("cannot extract public key")
	}
	defer C.CFRelease(C.CFTypeRef(val))

	return C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(val)),
		C.int(C.CFDataGetLength(val)),
	), nil
}

func newCFData(d []byte) (C.CFDataRef, error) {
	p := (*C.uchar)(C.CBytes(d))
	defer C.free(unsafe.Pointer(p))

	ref := C.CFDataCreate(C.kCFAllocatorDefault, p, C.CFIndex(len(d)))
	if ref == nilCFData {
		return ref, fmt.Errorf("error creating CFData")
	}

	return ref, nil
}

func newCFString(s string) (C.CFStringRef, error) {
	p := C.CString(s)
	defer C.free(unsafe.Pointer(p))

	ref := C.CFStringCreateWithCString(C.kCFAllocatorDefault, p, C.kCFStringEncodingUTF8)
	if ref == nilCFString {
		return ref, fmt.Errorf("error creating CFString")
	}
	return ref, nil
}

func newCFDictionary(m map[C.CFTypeRef]C.CFTypeRef) (C.CFDictionaryRef, error) {
	var (
		keys []unsafe.Pointer
		vals []unsafe.Pointer
	)

	for k, v := range m {
		keys = append(keys, unsafe.Pointer(k))
		vals = append(vals, unsafe.Pointer(v))
	}

	ref := C.CFDictionaryCreate(C.kCFAllocatorDefault, &keys[0], &vals[0], C.CFIndex(len(m)),
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks)
	return ref, nil
}

func goError(e interface{}) error {
	if e == nil {
		return nil
	}

	switch v := e.(type) {
	case C.OSStatus:
		if v == 0 {
			return nil
		}
		return osStatusError{code: int(v)}

	case C.CFErrorRef:
		if v == nilCFError {
			return nil
		}

		code := int(C.CFErrorGetCode(v))
		if desc := C.CFErrorCopyDescription(v); desc != nilCFString {
			defer C.CFRelease(C.CFTypeRef(desc))

			if cstr := C.CFStringGetCStringPtr(desc, C.kCFStringEncodingUTF8); cstr != nil {
				str := C.GoString(cstr)

				return fmt.Errorf("CFError %d (%s)", code, str)
			}

		}
		return fmt.Errorf("CFError %d", code)
	}

	return fmt.Errorf("unknown error type %T", e)
}

type osStatusError struct {
	code int
}

func (oserr osStatusError) Error() string {
	return fmt.Sprintf("OSStatus %d", oserr.code)
}
