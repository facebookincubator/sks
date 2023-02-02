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
#ifndef MIDTIER_H
#define MIDTIER_H

#include <string.h>

#include "macos.h"

/* Exported Functions */
size_t genKeyPair(const char*, const char*, int, int, unsigned char**, char**);
size_t signWithKey(
    const char*,
    const char*,
    unsigned char*,
    unsigned char*,
    size_t,
    unsigned char**,
    char**);
size_t
findPubKey(const char*, const char*, unsigned char*, unsigned char**, char**);
int deleteKey(const char*, const char*, unsigned char*, char**);
int updateKeyLabel(
    const char*,
    const char*,
    unsigned char*,
    const char*,
    char**);
#endif
