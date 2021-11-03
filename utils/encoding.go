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

import (
	"bytes"
	"encoding/gob"
)

// This file contains utility functions dealing with encoding and decoding

// MarshalBytes encodes arbitrary Go objects to a byte array
func MarshalBytes(object interface{}) ([]byte, error) {
	buffer := new(bytes.Buffer)
	enc := gob.NewEncoder(buffer)
	err := enc.Encode(object)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// UnmarshalBytes takes a byte array and decodes it into a Go object
func UnmarshalBytes(data []byte, object interface{}) error {
	buffer := new(bytes.Buffer)
	buffer.Write(data)

	dec := gob.NewDecoder(buffer)
	err := dec.Decode(object)
	if err != nil {
		return err
	}

	return nil
}
