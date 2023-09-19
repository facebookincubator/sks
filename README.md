# Secure Key Store

[![go.dev reference](https://img.shields.io/badge/Dev-reference-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/facebookincubator/sks)

Secure Key Store (SKS) is a Go library that abstracts the APIs provided by hardware security
modules present on most modern day user devices such as TPM and Secure Enclave, allowing
users to leverage their features through a single and simple API.

## Overview
In today's world, most user devices (such as laptops) are shipped with an embedded
hardware security device. Namely Macs come with a SoC called Secure Enclave (SE) while
most other manufacturers choose to use an implementation of the Trusted Platform Module (TPM).

These devices share common functionality such as key creation, signing and encryption,
however they differ significantly on how they operate and how their APIs are implemented.
SKS abstracts these discrepancies and provides users with a simple unified API that
allows them to create keys and use them to sign data.

## Hardware Support
We currently support the following hardware and platforms:
* TPM 2.0 on Linux
* TPM 2.0 on Windows
* Secure Enclave (T1 and T2 Chipsets) on macOS 10.14 and above

## Features and Status
The status of the library is **stable beta** - it can be used to interact with the
hardware but certain features might be missing or the API may change in future
releases without prior notice.

The library currently supports the following features:
* ECDSA P256 key creation.
* Searching for a key within the hardware.
* Signing of arbitrary data.
* Removal of keys from within the hardware.

The following will be implemented at later releases:
* AWS KMS support as a key store.

Some features do not work due to limitations of the platforms:
* Use of biometrics is not available on Linux and Windows.
* Use of key accessibility only when unlocked is not available on Linux and Windows.
* Key hierarchies are not exposed for TPM although they are used internally.

## The API
The library exposes a number of functions for creating and identifying a public/private key pair:

1. `NewKey(label, tag string, useBiometrics, accessibleWhenUnlockedOnly bool) (Key, error)`
This function generates a public/private key pair in the underlying hardware and returns
a structure implementing the `Key` interface or an error if it occurred. The key is
identified by two arbitrary strings the label and the tag. `useBiometrics` and
`accessibleWhenUnlockedOnly` have no effect on Linux. Currently this produces only ECSDA
P256 keys.

2. `FromLabelTag(labelTag string) Key`
This function constructs a `Key` identified by label and tag without looking up the key
in SKS. The public key of the structure implementing the `Key` interface is not populated.

The `Key` interface implements the `crypto.Signer` interface with some additional functions
specific to SKS.

1. `Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error)`
This function searches for the key identified by label and tag and instructs the
underlying hardware to sign the arbitrary data - typically the digest of the some
larger data set.

2. `Remove() error`
Try to remove the key from the hardware store. It returns `nil` or an error if it could
not remove the key.

3. `Hash() []byte`
Returns the SHA1 hash of the public portion of the key.

4. `Label() string`
Returns the label of the key.

5. `Tag() string`
Returns the tag of the key.

## Example Usage
```golang
key := sks.FromLabelTag("label:tag")
signer, _ := sks.NewKey(key.Label(), key.Tag(), false, true)

digest := make([]byte, 32)
rand.Read(digest)

signer.Sign(nil, digest, nil)

signer.Remove()
```

## License
SKS is published under the Apache v2.0 License.
