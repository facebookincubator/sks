// +build darwin

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

package macos

// TODO: If this C code gets larger move it to a separate .c file

/*
#cgo darwin LDFLAGS: -framework CoreFoundation -framework Security

#include "midtier.h"

typedef struct wrapper {
	unsigned char *buf;
	int status;
	size_t size;
	char *error;
} Wrapper;

Wrapper *wrapGenKey(const char *label, const char *tag, int useBiometrics, int accessibleWhenUnlockedOnly) {
	Wrapper *res = (Wrapper *)malloc(sizeof(Wrapper));
	if (!res)
		return NULL;
	memset(res, 0, sizeof(Wrapper));
	res->size = genKeyPair(label, tag, useBiometrics, accessibleWhenUnlockedOnly, &res->buf, &res->error);

	return res;
}

Wrapper *wrapSignWithKey(const char *label, const char *tag, void *hash, void *data, size_t len) {
	Wrapper *res = (Wrapper *)malloc(sizeof(Wrapper));
	if (!res)
		return NULL;
	memset(res, 0, sizeof(Wrapper));
	res->size = signWithKey(label, tag, (unsigned char *)hash, (unsigned char *)data, len, &res->buf, &res->error);

	return res;
}

Wrapper *wrapFindPubKey(const char *label, const char *tag, void *hash) {
	Wrapper *res = (Wrapper *)malloc(sizeof(Wrapper));
	if (!res)
		return NULL;
	memset(res, 0, sizeof(Wrapper));
	res->size = findPubKey(label, tag, (unsigned char *)hash, &res->buf, &res->error);

	return res;
}

Wrapper *wrapDeleteKey(const char *label, const char *tag, void *hash) {
	Wrapper *res = (Wrapper *)malloc(sizeof(Wrapper));
	if (!res)
		return NULL;
	memset(res, 0, sizeof(Wrapper));
	deleteKey(label, tag, (unsigned char *)hash, &res->error);

	return res;
}

Wrapper *wrapUpdateKeyLabel(const char *label, const char *tag, void *hash, const char *newLabel) {
	Wrapper *res = (Wrapper *)malloc(sizeof(Wrapper));
	if (!res)
		return NULL;
	memset(res, 0, sizeof(Wrapper));
	updateKeyLabel(label, tag, (unsigned char *)hash, newLabel, &res->error);

	return res;
}

Wrapper *wrapAccessibleWhenUnlockedOnly(const char *label, const char *tag, void *hash) {
	Wrapper *res = (Wrapper *)malloc(sizeof(Wrapper));
	if (!res)
		return NULL;
	memset(res, 0, sizeof(Wrapper));
	res->status = accessibleWhenUnlockedOnly(label, tag, (unsigned char *)hash, &res->error);

	return res;
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

// unwrap a Wrapper struct to a Go byte slice
// Free the underlying bufs so caller won't have to deal with them
func unwrap(w *C.Wrapper) (res []byte, err error) {
	defer C.free(unsafe.Pointer(w))
	if w == nil {
		return nil, errors.New("tried to unwrap empty response")
	}
	if w.error != nil {
		msg := C.GoString(w.error)
		err = errors.New(msg)
		C.free(unsafe.Pointer(w.error))
	}
	if w.buf != nil {
		res = C.GoBytes(unsafe.Pointer(w.buf), C.int(w.size))
		C.free(unsafe.Pointer(w.buf))
	}
	return
}

// unwrap a Wrapper struct to a Go byte slice
// Free the underlying bufs so caller won't have to deal with them
func unwrapStatus(w *C.Wrapper) (res int, err error) {
	defer C.free(unsafe.Pointer(w))
	if w == nil {
		return -1, errors.New("tried to unwrap empty response")
	}
	if w.error != nil {
		msg := C.GoString(w.error)
		err = errors.New(msg)
		C.free(unsafe.Pointer(w.error))
	}
	res = int(w.status)
	return
}

// GenKeyPair creates a key with the given label and tag potentially
// needing biometric authentication. Returns public key raw data.
func GenKeyPair(label, tag string, useBiometrics, accessibleWhenUnlockedOnly bool) ([]byte, error) {
	cl, ct := C.CString(label), C.CString(tag)
	cb, cu := C.int(0), C.int(0)
	if useBiometrics {
		cb = C.int(1)
	}
	if accessibleWhenUnlockedOnly {
		cu = C.int(1)
	}

	w := C.wrapGenKey(cl, ct, cb, cu)
	C.free(unsafe.Pointer(cl))
	C.free(unsafe.Pointer(ct))
	res, err := unwrap(w)
	if err != nil {
		return res, err
	}

	return res, nil
}

// SignWithKey signs arbitrary data pointed to by data with the key described by
// label and tag. Returns the signed data.
// hash is the SHA1 of the key. Can be nil
func SignWithKey(label, tag string, hash, data []byte) ([]byte, error) {
	cl, ct := C.CString(label), C.CString(tag)
	ch := C.CBytes(hash)
	cd := C.CBytes(data)
	clen := C.size_t(len(data))
	w := C.wrapSignWithKey(cl, ct, ch, cd, clen)
	C.free(unsafe.Pointer(ch))
	C.free(unsafe.Pointer(cd))
	C.free(unsafe.Pointer(cl))
	C.free(unsafe.Pointer(ct))

	res, err := unwrap(w)
	if err != nil {
		return res, err
	}

	return res, nil
}

// FindPubKey returns the raw public key described by label and tag
// hash is the SHA1 of the key. Can be nil
func FindPubKey(label, tag string, hash []byte) ([]byte, error) {
	cl, ct := C.CString(label), C.CString(tag)
	ch := C.CBytes(hash)
	w := C.wrapFindPubKey(cl, ct, ch)
	C.free(unsafe.Pointer(ch))
	C.free(unsafe.Pointer(cl))
	C.free(unsafe.Pointer(ct))

	res, err := unwrap(w)
	if err != nil {
		return res, err
	}

	return res, nil
}

// RemoveKey tries to delete a key identified by label, tag and hash.
// hash is the SHA1 of the key. Can be nil
// If hash is nil then all the keys that match the label and tag specified will
// be deleted.
// Returns true if the key was found and deleted successfully
func RemoveKey(label, tag string, hash []byte) (bool, error) {
	cl, ct := C.CString(label), C.CString(tag)
	ch := C.CBytes(hash)
	w := C.wrapDeleteKey(cl, ct, ch)
	C.free(unsafe.Pointer(ch))
	C.free(unsafe.Pointer(cl))
	C.free(unsafe.Pointer(ct))

	_, err := unwrap(w)
	if err != nil {
		return false, err
	}

	return true, nil
}

// AccessibleWhenUnlockedOnly checks whether or not the protection level for
// a key (identified by label, tag, and hash) is set to only accessible
// when the device is unlocked.
// hash is the SHA1 of the key. Can be nil
// Returns true if protection is set to accessible when unlocked only.
// False otherwise.
func AccessibleWhenUnlockedOnly(label, tag string, hash []byte) (bool, error) {
	cl, ct := C.CString(label), C.CString(tag)
	ch := C.CBytes(hash)
	w := C.wrapAccessibleWhenUnlockedOnly(cl, ct, ch)
	C.free(unsafe.Pointer(cl))
	C.free(unsafe.Pointer(ct))
	C.free(unsafe.Pointer(ch))

	status, err := unwrapStatus(w)
	if err != nil {
		return false, err
	}

	return status != 0, nil
}

// UpdateKeyLabel tries to update a key identified by label, tag and hash
// to a new label.
// hash is the SHA1 of the key. Can be nil
// Returns an error if the key could not be re-labeled.
func UpdateKeyLabel(label, tag, newLabel string, hash []byte) error {
	cl, ct, cn := C.CString(label), C.CString(tag), C.CString(newLabel)
	ch := C.CBytes(hash)
	w := C.wrapUpdateKeyLabel(cl, ct, ch, cn)
	C.free(unsafe.Pointer(ch))
	C.free(unsafe.Pointer(cl))
	C.free(unsafe.Pointer(ct))
	C.free(unsafe.Pointer(cn))

	_, err := unwrap(w)
	if err != nil {
		return err
	}

	return nil
}
