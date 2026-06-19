//go:build linux
// +build linux

// Copyright (c) Meta Platforms, Inc. and affiliates.
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
	"testing"

	"github.com/facebookincubator/sks/diskio"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpmutil"
)

// newSimDevice returns a tpmDevice backed by an in-process TPM simulator and an
// isolated on-disk key store.
func newSimDevice(t *testing.T) *tpmDevice {
	t.Helper()
	// diskio.OpenDB resolves its location once from XDG_DATA_HOME; point it at a
	// throwaway directory so the test does not touch a real key store.
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	sim, err := simulator.Get()
	if err != nil {
		t.Fatalf("failed to start TPM simulator: %v", err)
	}
	t.Cleanup(func() { sim.Close() })

	return &tpmDevice{
		rwc:        sim,
		keyHandler: NewKeyHandler(map[string]tpmutil.Handle{}),
	}
}

// TestEnumerateKeys checks that EnumerateKeys returns every user key with a
// public key and excludes the internal organization root key.
func TestEnumerateKeys(t *testing.T) {
	tpm := newSimDevice(t)

	want := []string{"key-one", "key-two"}
	for _, label := range want {
		if _, err := tpm.GenKeyPair(label); err != nil {
			t.Fatalf("GenKeyPair(%q): %v", label, err)
		}
	}

	infos, err := tpm.EnumerateKeys()
	if err != nil {
		t.Fatalf("EnumerateKeys: %v", err)
	}

	got := make(map[string]bool, len(infos))
	for _, info := range infos {
		if info.Label == diskio.OrgRootKey {
			t.Errorf("EnumerateKeys returned the internal %q key", diskio.OrgRootKey)
		}
		if len(info.PublicKey) == 0 {
			t.Errorf("key %q has an empty public key", info.Label)
		}
		if info.Created.IsZero() {
			t.Errorf("key %q has no creation time", info.Label)
		}
		got[info.Label] = true
	}

	for _, label := range want {
		if !got[label] {
			t.Errorf("EnumerateKeys did not return key %q", label)
		}
	}
	if len(infos) != len(want) {
		t.Errorf("EnumerateKeys returned %d keys, want %d", len(infos), len(want))
	}
}
