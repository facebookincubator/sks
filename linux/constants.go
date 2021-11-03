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
	"github.com/google/go-tpm/tpmutil"
)

// This file contains constants needed for Linux use accessing the TPM.

// DefaultEKAuthPolicy is the default auth policy for an Endorsement Key. See
// https://trustedcomputinggroup.org/resource/tcg-ek-credential-profile-for-tpm-family-2-0/
// for details.
var DefaultEKAuthPolicy = []byte{
	0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
	0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
	0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
	0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
	0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
	0x69, 0xAA,
}

const (
	// TPMOrgPersistentMin is the minimum handle SKS will use for persistent,
	// evicted objects.
	TPMOrgPersistentMin tpmutil.Handle = 0x8101fb00

	// TPMOrgSRKHandle is the handle where the organization root key is
	// persisted.
	TPMOrgSRKHandle = TPMOrgPersistentMin + iota
)
