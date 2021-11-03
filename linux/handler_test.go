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
	"runtime"
	"testing"

	"github.com/google/go-tpm/tpmutil"
)

func TestKeyHandler(t *testing.T) {
	const (
		dev = "device-key"
		ssh = "ssh-key"
		foo = "foo-key"
		bar = "bar-key"
	)
	m := map[string]tpmutil.Handle{
		dev: TPMOrgPersistentMin + 0x0a,
		ssh: TPMOrgPersistentMin + 0x0c,
	}

	h := NewKeyHandler(m)

	got, flush, err := h.Get(dev)
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	flush(true)
	want := TPMOrgPersistentMin + 0x0a
	if got != want {
		t.Fatalf("Get() wrong handle: got %#x, want %#x", got, want)
	}

	got, flush, err = h.Get(foo)
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	want = TPMOrgPersistentMin + 0x0b
	if got != want {
		t.Fatalf("Get() wrong handle: got %#x, want %#x", got, want)
	}
	flush(false)

	got, flush, err = h.Get(bar)
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	want = TPMOrgPersistentMin + 0x0b
	if got != want {
		t.Fatalf("Get() wrong handle: got %#x, want %#x", got, want)
	}
	flush(true)

	got, flush, err = h.Get(foo)
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	want = TPMOrgPersistentMin + 0x0d
	if got != want {
		t.Fatalf("Get() wrong handle: got %#x, want %#x", got, want)
	}
	flush(true)

	got, _, err = h.Get(bar)
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	want = TPMOrgPersistentMin + 0x0b
	if got != want {
		t.Fatalf("Get() wrong handle: got %#x, want %#x", got, want)
	}
}

func TestOrderingGetRemove(t *testing.T) {
	const dev = "device-key"
	m := map[string]tpmutil.Handle{
		dev: TPMOrgPersistentMin + 0x0a,
	}

	h := NewKeyHandler(m)

	for i := 0; i < 1000; i++ {
		_, flush, err := h.Get(dev)
		if err != nil {
			t.Fatalf("Get() error: %v", err)
		}

		order := make(chan int, 2)

		go func() {
			flush := h.Remove(dev)
			order <- 1
			flush(true)
		}()
		runtime.Gosched()
		order <- 0
		flush(true)

		first := <-order
		second := <-order
		if first != 0 || second != 1 {
			t.Fatalf("Wrong order: got (%d, %d), want (0, 1)", first, second)
		}
	}
}

func TestOrderingRemoveGet(t *testing.T) {
	const dev = "device-key"
	m := map[string]tpmutil.Handle{
		dev: TPMOrgPersistentMin + 0x0a,
	}

	h := NewKeyHandler(m)

	for i := 0; i < 1000; i++ {
		flush := h.Remove(dev)

		order := make(chan int, 2)

		go func() {
			_, flush, _ := h.Get(dev)
			order <- 1
			flush(true)
		}()
		runtime.Gosched()
		order <- 0
		flush(true)

		first := <-order
		second := <-order
		if first != 0 || second != 1 {
			t.Fatalf("Wrong order: got (%d, %d), want (0, 1)", first, second)
		}
	}
}
