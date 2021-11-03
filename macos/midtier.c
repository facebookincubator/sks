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
#include "midtier.h"

unsigned char* CFDataToUint8(CFDataRef data) {
  CFIndex len = CFDataGetLength(data);
  if (!len)
    return NULL;

  UInt8* buf = (UInt8*)malloc((size_t)len);
  if (!buf)
    return NULL;
  memset(buf, 0, (size_t)len);

  CFRange range = CFRangeMake(0, len);
  CFDataGetBytes(data, range, buf);

  return (unsigned char*)buf;
}

// CFStringToCString creates a copy of the bytes of data
// converted to UTF-8 encoding.
char* CFStringToCString(CFStringRef data) {
  CFIndex len = CFStringGetLength(data);
  if (!len)
    return NULL;

  CFIndex realLen =
      CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8);
  char* buf = (char*)malloc((size_t)realLen + 1);
  if (!buf)
    return NULL;
  memset(buf, 0, (size_t)realLen + 1);

  Boolean ok =
      CFStringGetCString(data, buf, realLen + 1, kCFStringEncodingUTF8);
  if (!ok)
    return NULL;

  return buf;
}

/// genKeyPair generates a public/private key pair and returns the raw
// key data of the public key. It returns null on error.
size_t genKeyPair(
    const char* label,
    const char* tag,
    int useBiometrics,
    int accessibleWhenUnlockedOnly,
    unsigned char** ret,
    char** error) {
  CFBooleanRef biometrics = kCFBooleanFalse;
  CFBooleanRef keyProtection = kCFBooleanFalse;

  if (useBiometrics)
    biometrics = kCFBooleanTrue;
  if (accessibleWhenUnlockedOnly)
    keyProtection = kCFBooleanTrue;

  CFDataRef pubKey = NULL;
  CFStringRef errStr = NULL;

  CFBooleanRef success =
      CreateSEKey(label, tag, biometrics, keyProtection, &pubKey, &errStr);

  if ((errStr) || (!success)) {
    if (!errStr) {
      errStr = CFSTR("error generating key pair");
    }
    *error = CFStringToCString(errStr);
    CFRelease((CFTypeRef)errStr);
    return 0;
  }

  if (!pubKey)
    return 0;

  *ret = CFDataToUint8(pubKey);
  CFIndex size = CFDataGetLength(pubKey);
  CFRelease((CFTypeRef)pubKey);
  return (size_t)size;
}

// signWithKey signs arbitrary data with the key specified by label and tag
// It returns the signed data or null on error
// Hash is the SHA1 of the public key. Can be NULL.
size_t signWithKey(
    const char* label,
    const char* tag,
    unsigned char* hash,
    unsigned char* data,
    size_t len,
    unsigned char** ret,
    char** error) {
  if (!len)
    return 0;

  CFStringRef errStr = NULL;

  CFDataRef dataRef =
      CFDataCreate(kCFAllocatorDefault, (UInt8*)data, (CFIndex)len);
  if (!dataRef) {
    errStr = SecCopyErrorMessageString(errSecAllocate, NULL);
    *error = CFStringToCString(errStr);
    CFRelease((CFTypeRef)errStr);
    return 0;
  }

  CFDataRef res = SignWithSEKey(label, tag, hash, dataRef, &errStr);
  CFRelease((CFTypeRef)dataRef);
  if (errStr) {
    *error = CFStringToCString(errStr);
    CFRelease((CFTypeRef)errStr);
    return 0;
  }
  if (!res)
    return 0;

  *ret = CFDataToUint8(res);
  CFIndex size = CFDataGetLength(res);
  CFRelease((CFTypeRef)res);
  return (size_t)size;
}

// findPubKey returns the raw public key data for the key key specified by label
// and tag. Returns null if an error occured or no key is found.
// Hash is the SHA1 of the public key. Can be NULL.
size_t findPubKey(
    const char* label,
    const char* tag,
    unsigned char* hash,
    unsigned char** ret,
    char** error) {
  CFDataRef pubKey = NULL;
  OSStatus status = FetchSEKey(label, tag, hash, &pubKey);
  if (status != errSecSuccess && status != errSecItemNotFound) {
    CFStringRef errStr = SecCopyErrorMessageString(status, NULL);
    *error = CFStringToCString(errStr);
    CFRelease((CFTypeRef)errStr);
    return 0;
  }
  if (!pubKey)
    return 0;

  *ret = CFDataToUint8(pubKey);
  CFIndex size = CFDataGetLength(pubKey);
  CFRelease((CFTypeRef)pubKey);
  return (size_t)size;
}

// deleteKey deletes the key specified by label, tag and, potentially, a hash.
// The hash is the SHA1 hash for the key and key be NULL.
// In cases where the hash is not specified and many keys share the same label
// and tag combination, all of these keys will be deleted.
// It returns 1 on success 0 on failure.
int deleteKey(
    const char* label,
    const char* tag,
    unsigned char* hash,
    char** error) {
  OSStatus status = DeleteKey(label, tag, hash);
  if (status != errSecSuccess) {
    CFStringRef errStr = SecCopyErrorMessageString(status, NULL);
    *error = CFStringToCString(errStr);
    CFRelease((CFTypeRef)errStr);
    return 0;
  }

  return 1;
}

// accessibleWhenUnlockedOnly checks the protection attribute for a key
// specified by label and tag.
// The hash is the SHA1 hash for the key and key be NULL.
// Returns 0 if an error occured or no key protection attribute is found.
// It returns 1 if the key is only accessible when the device is unlocked.
// 0 otherwise.
int accessibleWhenUnlockedOnly(
    const char* label,
    const char* tag,
    unsigned char* hash,
    char** error) {
  CFStringRef errStr = NULL;
  CFTypeRef protection = HasSEKeyProtection(
      label, tag, hash, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, &errStr);

  if (errStr || !protection) {
    if (!errStr) {
      errStr = CFSTR("error determining key protection level");
    }
    *error = CFStringToCString(errStr);
    CFRelease((CFTypeRef)errStr);
    return 0;
  }

  if (CFEqual(protection, kSecAttrAccessibleWhenUnlockedThisDeviceOnly)) {
    return 1;
  }

  return 0;
}

// updateKeyLabel changes the key's label to a new one.
int updateKeyLabel(
    const char* label,
    const char* tag,
    unsigned char* hash,
    const char* newLabel,
    char** error) {
  OSStatus status = UpdateKeyLabel(label, tag, hash, newLabel);
  if (status != errSecSuccess) {
    CFStringRef errStr = SecCopyErrorMessageString(status, NULL);
    *error = CFStringToCString(errStr);
    CFRelease((CFTypeRef)errStr);
    return 0;
  }

  return 1;
}
