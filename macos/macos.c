/* This file contains the main SE key functions.
 * They're considered to be low-level so for most use cases callers should use
 * the functions described in midtier.h
 */
/*
Copyright (c) Facebook, Inc. and its affiliates.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "macos.h"

// Turn a regular C string to CFDataRef
// We always assume UTF8 encoding.
CFDataRef StringToDataRef(const char* str) {
  CFStringRef s = CFStringCreateWithCString(
      kCFAllocatorDefault, str, kCFStringEncodingUTF8);
  CFDataRef res = CFStringCreateExternalRepresentation(
      kCFAllocatorDefault, s, kCFStringEncodingUTF8, 0);

  if (s)
    CFRelease((CFTypeRef)s);

  return res;
}

// Extract the public key data from a SecKeyRef
// Returns null if it couldn't find the data
CFDataRef ExtractPubKey(SecKeyRef pubKey) {
  CFDataRef val = NULL;
  CFDataRef res = NULL;
  CFDictionaryRef keyAttrs = SecKeyCopyAttributes(pubKey);
  if (CFDictionaryContainsKey(keyAttrs, kSecValueData) == true)
    val = (CFDataRef)CFDictionaryGetValue(keyAttrs, kSecValueData);

  if (val)
    res = CFDataCreateCopy(kCFAllocatorDefault, val);

  if (keyAttrs)
    CFRelease((CFTypeRef)keyAttrs);

  return res;
}

// Fetch a single key
// Key is searched with an application tag and a label
// Returns the status of the operation as OSStatus
// If the operation was successful it also populates pubKey,
// hash is the public key's SHA1 hash, can be set to NULL.
OSStatus FetchSEPrivKeyRef(
    const char* label,
    const char* tag,
    unsigned char* hash,
    SecKeyRef* privKey) {
  CFMutableDictionaryRef query =
      CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);
  CFDataRef cfTag = StringToDataRef(tag);
  CFStringRef cfLabel = CFStringCreateWithCString(
      kCFAllocatorDefault, label, kCFStringEncodingUTF8);
  CFDictionaryAddValue(query, kSecClass, kSecClassKey);
  CFDictionaryAddValue(query, kSecAttrKeyType, kSecAttrKeyTypeEC);
  CFDictionaryAddValue(query, kSecAttrApplicationTag, cfTag);
  CFDictionaryAddValue(query, kSecAttrLabel, cfLabel);
  CFDictionaryAddValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
  CFDictionaryAddValue(query, kSecReturnRef, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitOne);

  if (hash) {
    CFDataRef h = CFDataCreateWithBytesNoCopy(
        kCFAllocatorDefault, (UInt8*)hash, 20, kCFAllocatorNull);
    CFDictionaryAddValue(query, kSecAttrApplicationLabel, h);
  }

  SecKeyRef key = NULL;
  OSStatus status = SecItemCopyMatching(query, (CFTypeRef*)&key);
  CFRelease((CFTypeRef)query);
  CFRelease((CFTypeRef)cfTag);
  CFRelease((CFTypeRef)cfLabel);

  if ((status != errSecSuccess) || (!key))
    return status;

  if (privKey)
    *privKey = key;

  return status;
}

// Like FetchSEPrivKeyRef but populates pubKey with the raw key data
// hash is the SHA1 hash of the public key
OSStatus FetchSEKey(
    const char* label,
    const char* tag,
    unsigned char* hash,
    CFDataRef* pubKey) {
  SecKeyRef key = NULL;
  OSStatus status = FetchSEPrivKeyRef(label, tag, hash, &key);

  if ((status != errSecSuccess && status != errSecItemNotFound) || !key)
    goto __cleanup;

  if (pubKey) {
    SecKeyRef pkey = SecKeyCopyPublicKey(key);
    *pubKey = ExtractPubKey(pkey);
    CFRelease(pkey);
  }

__cleanup:
  if (key)
    CFRelease((CFTypeRef)key);

  return status;
}

// Creates a key in SE
// Returns the status of the operation as OSStatus
// If it is successful it will populate pubKey
CFBooleanRef CreateSEKey(
    const char* label,
    const char* tag,
    CFBooleanRef useBiometrics,
    CFBooleanRef accessibleWhenUnlockedOnly,
    CFDataRef* pubKey,
    CFStringRef* errorStr) {
  CFErrorRef error = NULL;
  CFTypeRef protection = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
  SecAccessControlCreateFlags flags = kSecAccessControlPrivateKeyUsage;

  if (useBiometrics == kCFBooleanTrue)
    flags |= kSecAccessControlUserPresence;
  if (accessibleWhenUnlockedOnly == kCFBooleanTrue)
    protection = kSecAttrAccessibleWhenUnlockedThisDeviceOnly;

  SecAccessControlRef access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault, protection, flags, &error);

  if (error) {
    *errorStr = CFErrorCopyDescription(error);
    CFRelease((CFTypeRef)error);
    return kCFBooleanFalse;
  }

  CFDataRef cfTag = StringToDataRef(tag);
  CFStringRef cfLabel = CFStringCreateWithCString(
      kCFAllocatorDefault, label, kCFStringEncodingUTF8);
  CFMutableDictionaryRef privKeyAttrs = CFDictionaryCreateMutable(
      kCFAllocatorDefault,
      0,
      &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(privKeyAttrs, kSecAttrApplicationTag, cfTag);
  CFDictionaryAddValue(privKeyAttrs, kSecAttrAccessControl, access);
  CFDictionaryAddValue(privKeyAttrs, kSecAttrIsPermanent, kCFBooleanTrue);

  CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
      kCFAllocatorDefault,
      0,
      &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(attrs, kSecAttrLabel, cfLabel);
  CFDictionaryAddValue(attrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
  CFDictionaryAddValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeEC);
  CFDictionaryAddValue(attrs, kSecPrivateKeyAttrs, privKeyAttrs);

  SecKeyRef privKey = SecKeyCreateRandomKey(attrs, &error);
  CFRelease((CFTypeRef)access);
  CFRelease((CFTypeRef)privKeyAttrs);
  CFRelease((CFTypeRef)attrs);
  CFRelease((CFTypeRef)cfTag);
  CFRelease((CFTypeRef)cfLabel);

  if ((!privKey) || (error)) {
    *errorStr = CFSTR("error generating random private key");
    if (error) {
      *errorStr = CFErrorCopyDescription(error);
      CFRelease((CFTypeRef)error);
    }
    return kCFBooleanFalse;
  }

  SecKeyRef publicKey = SecKeyCopyPublicKey(privKey);
  CFRelease((CFTypeRef)privKey);

  if (publicKey)
    *pubKey = ExtractPubKey(publicKey);

  CFRelease((CFTypeRef)publicKey);
  return kCFBooleanTrue;
}

// Sign the data provided with the key identified by the tag and label provided
// Returns the signature or NULL on error
CFDataRef SignWithSEKey(
    const char* label,
    const char* tag,
    unsigned char* hash,
    CFDataRef data,
    CFStringRef* errorStr) {
  SecKeyRef key = NULL;
  OSStatus status = FetchSEPrivKeyRef(label, tag, hash, &key);
  if (status != errSecSuccess) {
    *errorStr = SecCopyErrorMessageString(status, NULL);
    return NULL;
  }
  if (!key)
    return NULL;

  CFErrorRef error = NULL;
  CFDataRef res = SecKeyCreateSignature(
      key, kSecKeyAlgorithmECDSASignatureDigestX962, data, &error);
  CFRelease((CFTypeRef)key);

  if (error) {
    *errorStr = CFErrorCopyDescription(error);
    CFRelease((CFTypeRef)error);
    return NULL;
  }

  return res;
}

// Delete the specified key, identified by tag, label and, potentially, a hash.
// The hash is the SHA1 hash of the key. Can be NULL
OSStatus DeleteKey(const char* label, const char* tag, unsigned char* hash) {
  CFDataRef cfTag = StringToDataRef(tag);
  CFStringRef cfLabel = CFStringCreateWithCString(
      kCFAllocatorDefault, label, kCFStringEncodingUTF8);

  CFMutableDictionaryRef query =
      CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);
  CFDictionaryAddValue(query, kSecClass, kSecClassKey);
  CFDictionaryAddValue(query, kSecAttrKeyType, kSecAttrKeyTypeEC);
  CFDictionaryAddValue(query, kSecAttrApplicationTag, cfTag);
  CFDictionaryAddValue(query, kSecAttrLabel, cfLabel);
  CFDictionaryAddValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);

  if (hash) {
    CFDataRef h = CFDataCreateWithBytesNoCopy(
        kCFAllocatorDefault, (UInt8*)hash, 20, kCFAllocatorNull);
    CFDictionaryAddValue(query, kSecAttrApplicationLabel, h);
  }

  OSStatus res;
  do {
    res = SecItemDelete(query);
  } while (res == errSecDuplicateItem);

  return res;
}

OSStatus UpdateKeyLabel(
    const char* label,
    const char* tag,
    unsigned char* hash,
    const char* newLabel) {
  CFDataRef cfTag = StringToDataRef(tag);
  CFStringRef cfLabel = CFStringCreateWithCString(
      kCFAllocatorDefault, label, kCFStringEncodingUTF8);
  CFStringRef cfNewLabel = CFStringCreateWithCString(
      kCFAllocatorDefault, newLabel, kCFStringEncodingUTF8);

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
      NULL,
      0,
      &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(query, kSecClass, kSecClassKey);
  CFDictionaryAddValue(query, kSecAttrApplicationTag, cfTag);
  CFDictionaryAddValue(query, kSecAttrLabel, cfLabel);
  CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitOne);

  CFMutableDictionaryRef toUpdate = CFDictionaryCreateMutable(
      kCFAllocatorDefault,
      0,
      &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);

  CFDictionaryAddValue(toUpdate, kSecAttrLabel, cfNewLabel);

  OSStatus status = SecItemUpdate(query, toUpdate);
  CFRelease((CFTypeRef)query);
  CFRelease((CFTypeRef)toUpdate);
  CFRelease((CFTypeRef)cfTag);
  CFRelease((CFTypeRef)cfLabel);
  CFRelease((CFTypeRef)cfNewLabel);

  return status;
}
