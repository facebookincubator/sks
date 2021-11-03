// Package utils implements basic utilities needed for the library

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

package utils

import "math/big"

// This file contains utility functions and structs for dealing with
// cryptographic operations.

// ECCPublicKey is the bare minimum data needed for an ECC public key. The
// standard public key structs have more data than is usable when marshaling.
type ECCPublicKey struct {
	X, Y *big.Int
}

// ECCSignature is the bare minumum of ECC signatures needed. The standard ECC
// signature structs available in other tools and libraries include fields we
// can't include when marshaling.
type ECCSignature struct {
	R, S *big.Int
}
