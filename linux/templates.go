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

// This file contains all the templates needed for Linux TPM usage.

import (
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// TODO: Provide a default RSA template

// DefaultECCEKTemplate generates a default template for use when generating an
// ECC key. This template is suitable for use generating an organization
// Endorsement Key for a user.
// See section 2.1.5.2 of https://fburl.com/tpmcredentialprofileekv14 for
// details on the TSS standard ECC EK template, but note this differs.
// NOTE: Modifying this template will modify any primary key generated using
// it. Modify this function at your own peril.
func DefaultECCEKTemplate() tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
			tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy:    DefaultEKAuthPolicy,
		ECCParameters: DefaultECCEKParameters(),
	}
}

// DefaultECCEKParameters generates the default ECC parameters for use when
// generating an ECC Endorsement Key. See section 2.1.5.2 of
// https://fburl.com/tpmcredentialprofileekv14 for details.
// NOTE: Modifying these parameters will modify any primary key generated using
// them. Modify this function at your own peril.
func DefaultECCEKParameters() *tpm2.ECCParams {
	return &tpm2.ECCParams{
		CurveID: tpm2.CurveNISTP256,
		Point: tpm2.ECPoint{
			XRaw: big.NewInt(0).Bytes(),
			YRaw: big.NewInt(0).Bytes(),
		},
		Symmetric: &tpm2.SymScheme{
			Alg:     tpm2.AlgAES,
			KeyBits: 128,
			Mode:    tpm2.AlgCFB,
		},
	}
}

// TODO: Provide a default encrypting key template

// DefaultECCKeyTemplate is the default template to use when generating an ECC
// signing key for general use.
// NOTE: Modifying this template will modify any primary key generated using
// it. Modify this function at your own peril.
func DefaultECCKeyTemplate() tpm2.Public {
	tmpl := DefaultECCEKTemplate()

	tmpl.Attributes &= ^tpm2.FlagDecrypt
	tmpl.Attributes &= ^tpm2.FlagRestricted
	tmpl.Attributes |= tpm2.FlagNoDA
	tmpl.Attributes |= tpm2.FlagSign

	tmpl.ECCParameters.Sign = &tpm2.SigScheme{
		Alg:  tpm2.AlgECDSA,
		Hash: tpm2.AlgSHA256,
	}
	tmpl.ECCParameters.Symmetric = &tpm2.SymScheme{}

	return tmpl
}
