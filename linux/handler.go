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
	"fmt"
	"sort"
	"sync"

	"github.com/google/go-tpm/tpmutil"
)

const (
	minValidHandle tpmutil.Handle = TPMOrgPersistentMin + 0x0a
	maxValidHandle tpmutil.Handle = TPMOrgPersistentMin + 0xff
)

// KeyHandler stores mapping between key label and key handle.
type KeyHandler struct {
	lock    sync.Mutex
	handles map[string]tpmutil.Handle

	inFlightLocks   map[string]*sync.Mutex
	inFlightHandles map[string]tpmutil.Handle
}

// NewKeyHandler returns an instance of KeyHandler.
func NewKeyHandler(handles map[string]tpmutil.Handle) KeyHandler {
	if handles == nil {
		handles = make(map[string]tpmutil.Handle)
	}

	return KeyHandler{
		handles: handles,

		inFlightLocks:   make(map[string]*sync.Mutex),
		inFlightHandles: make(map[string]tpmutil.Handle),
	}
}

// Get returns handle for given keyID if present, otherwise
// return next available handle and callback which should be called
// after tpm key initialization. success indicates whether
// tpm key initialization was successful or not.
func (h *KeyHandler) Get(keyID string) (tpmutil.Handle, func(success bool), error) {
	lock := h.lockKey(keyID)

	h.lock.Lock()
	defer h.lock.Unlock()

	handle, ok := h.handles[keyID]
	if ok {
		return handle, func(bool) { lock.Unlock() }, nil
	}

	next, err := h.nextAvailable()
	if err != nil {
		return 0, nil, err
	}

	h.inFlightHandles[keyID] = next

	flush := func(success bool) {
		h.lock.Lock()
		if success {
			h.handles[keyID] = next
		}
		delete(h.inFlightLocks, keyID)
		delete(h.inFlightHandles, keyID)
		lock.Unlock()
		h.lock.Unlock()
	}

	return next, flush, nil
}

func (h *KeyHandler) lockKey(keyID string) *sync.Mutex {
	var ret *sync.Mutex
	for stop := false; !stop; {
		h.lock.Lock()
		lock := h.inFlightLocks[keyID]
		if lock == nil {
			lock = new(sync.Mutex)
			h.inFlightLocks[keyID] = lock
		}
		h.lock.Unlock()

		ret = lock
		ret.Lock()

		h.lock.Lock()
		lock = h.inFlightLocks[keyID]
		if ret == lock {
			stop = true
		} else {
			ret.Unlock()
		}
		h.lock.Unlock()
	}
	return ret
}

// Remove deletes handle with given keyID from KeyHandler if present.
func (h *KeyHandler) Remove(keyID string) func(success bool) {
	lock := h.lockKey(keyID)

	return func(success bool) {
		h.lock.Lock()
		if success {
			delete(h.handles, keyID)
		}
		delete(h.inFlightHandles, keyID)
		lock.Unlock()
		h.lock.Unlock()
	}
}

func handlesToSlice(m map[string]tpmutil.Handle, dst []tpmutil.Handle) []tpmutil.Handle {
	for _, key := range m {
		if key >= minValidHandle {
			dst = append(dst, key)
		}
	}
	return dst
}

// nextAvailable returns next key handle available in KeyHandler,
// tries to fill gaps if possible.
func (h *KeyHandler) nextAvailable() (tpmutil.Handle, error) {
	l := len(h.handles) + len(h.inFlightHandles)
	if l == 0 {
		return minValidHandle, nil
	}
	if tpmutil.Handle(l) >= maxValidHandle-minValidHandle+1 {
		return 0, fmt.Errorf("no more key handles available")
	}

	keys := handlesToSlice(h.handles, nil)
	keys = handlesToSlice(h.inFlightHandles, keys)

	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	ret := keys[0]
	for _, key := range keys {
		if ret != key {
			return ret, nil
		}
		ret++
	}

	return ret, nil
}
