/* Used for the MacOS definitions primarily for low level SE functionality */
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
#ifndef MACOS_H
#define MACOS_H

/* Includes */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

/* Exported functions */
OSStatus FetchSEKey(const char*, const char*, unsigned char*, CFDataRef*);
CFBooleanRef CreateSEKey(
    const char*,
    const char*,
    CFBooleanRef,
    CFBooleanRef,
    CFDataRef*,
    CFStringRef*);
CFDataRef SignWithSEKey(
    const char*,
    const char*,
    unsigned char*,
    CFDataRef,
    CFStringRef*);
OSStatus DeleteKey(const char*, const char*, unsigned char*);
CFTypeRef HasSEKeyProtection(
    const char*,
    const char*,
    unsigned char*,
    CFStringRef,
    CFStringRef*);
OSStatus UpdateKeyLabel(const char*, const char*, unsigned char*, const char*);

#endif
