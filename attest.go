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
	"fmt"
	"github.com/facebookincubator/sks/attest"
)

// GetSecureHardwareVendorData gets vendor specific information from the secure
// hardware implementation available for a given device
func GetSecureHardwareVendorData() (*attest.SecureHardwareVendorData, error) {
	data, err := getSecureHardwareVendorData()
	if err != nil {
		return nil, fmt.Errorf(ErrGetSecureHardwareVendorData, err)
	}

	return data, nil
}
