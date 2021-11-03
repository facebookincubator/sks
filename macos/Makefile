# Copyright (c) Facebook, Inc. and its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LDFLAGS= -framework CoreFoundation -framework Security
CCFLAGS= -I. -Wall
ARFLAGS= rv
CC= gcc
AR= ar
LIBDIR= ../lib
SRCS= $(wildcard *.c)
OBJS_AMD64= $(SRCS:.c=_amd64.o)
OBJS_ARM64= $(SRCS:.c=_arm64.o)
MAIN= sks
TARGET_ARM64= -target arm64-apple-macos11
TARGET_AMD64= -target x86_64-apple-macos10.12

all: $(OBJS_ARM64) $(OBJS_AMD64) libs ar
	lipo -create -o $(LIBDIR)/$(MAIN).so $(LIBDIR)/sks_amd64.so $(LIBDIR)/sks_arm64.so
	lipo -create -o $(LIBDIR)/$(MAIN).dylib $(LIBDIR)/sks_amd64.dylib $(LIBDIR)/sks_arm64.dylib
	lipo -create -o $(LIBDIR)/$(MAIN).a $(LIBDIR)/sks_amd64.a $(LIBDIR)/sks_arm64.a

libs:
	$(CC) $(LDFLAGS) -bundle -o $(LIBDIR)/$(MAIN)_amd64.so $(OBJS_AMD64) $(TARGET_AMD64)
	$(CC) $(LDFLAGS) -shared -o $(LIBDIR)/$(MAIN)_amd64.dylib $(OBJS_AMD64) $(TARGET_AMD64)
	$(CC) $(LDFLAGS) -bundle -o $(LIBDIR)/$(MAIN)_arm64.so $(OBJS_ARM64) $(TARGET_ARM64)
	$(CC) $(LDFLAGS) -shared -o $(LIBDIR)/$(MAIN)_arm64.dylib $(OBJS_ARM64) $(TARGET_ARM64)

%_amd64.o : %.c
	$(CC) $(CCFLAGS) $(TARGET_AMD64) -c $< -o $@

%_arm64.o : %.c
	$(CC) $(CCFLAGS) $(TARGET_ARM64) -c $< -o $@

ar: $(OBJS_ARM64) $(OBJS_AMD64)
	$(AR) $(ARFLAGS) $(LIBDIR)/$(MAIN)_amd64.a $(OBJS_AMD64)
	$(AR) $(ARFLAGS) $(LIBDIR)/$(MAIN)_arm64.a $(OBJS_ARM64)

clean:
	rm -f *.o
	rm -f $(LIBDIR)/*.so
	rm -f $(LIBDIR)/*.dylib
	rm -f $(LIBDIR)/*.a
