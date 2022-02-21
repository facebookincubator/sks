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

// Define the error messages' patterns that are common across platforms
const (
	ErrGenKeyPair            = "sks: error while generating key pair with label %q and tag %q: %w"
	ErrSignWithKey           = "sks: error while signing with key with label %q and tag %q: %w"
	ErrFindPubKey            = "sks: error while trying to find key with label %q and tag %q: %w"
	ErrFindPubKeyNil         = "sks: nil key returned for key with label %q and tag %q"
	ErrRemoveKey             = "sks: error while trying to remove key with label %q and tag %q: %w"
	ErrLabelOrTagUnspecified = "sks: you must specify both a label and a tag"
	ErrAttributeLookup       = "sks: error while looking up attributes for key with label %q and tag %q: %w"
	ErrUpdateKeyAttr         = "sks: error updating attribute for key with label %q and tag %q"
	ErrNotImplemented        = "sks: %q method not implemented"
)
