// Package diskio implements basic operations for saving SKS related information
// on disk.
//
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
//
package diskio

import (
	"sync"

	"github.com/peterbourgon/diskv"
)

// KeyValueStore is a thin wrapper around Diskv. It requires only the functions
// actually used here to allow us to mock calls. Accordingly, the documentation
// for the interface methods is basically the Diskv documentation, since that is
// the contract to be fulfilled.
type KeyValueStore interface {
	// Read reads the key and returns the value.
	Read(key string) ([]byte, error)

	// Write synchronously writes the key-value pair to disk, making it
	// immediately available for reads. Write relies on the filesystem to
	// perform an eventual sync to physical media.
	Write(key string, val []byte) error

	// Has returns true if the given key exists.
	Has(key string) bool

	// Erase synchronously erases the given key from the disk (and the cache, if
	// one is in use).
	Erase(key string) error

	// Keys returns a channel that will yield every key accessible by the store,
	// in undefined order. If a cancel channel is provided, closing it will
	// terminate and close the keys channel.
	Keys(cancel <-chan struct{}) <-chan string
}

// Database defines an interface for a database utility
type Database interface {
	// Load loads the data from the DB with the specified key.
	Load(key string) ([]byte, error)

	// Save puts bytes in the bucket. For a new item, set key to the empty
	// string if you want a key automatically chosen for you. Returns the key
	// used for saving data and any error that occurred.
	Save(key string, value []byte) (string, error)

	// HasKey returns true if the key is in the DB, false if not
	HasKey(key string) bool

	// Delete deletes a key from the database
	Delete(key string) error

	// List returns all keys
	List() ([]string, error)

	// Visit visits all keys in undefined order, calling visitor for each key-value pair.
	Visit(visitor func(key string, val []byte) error) error
}

type diskKVStore struct {
	db  *diskv.Diskv
	mux sync.RWMutex
}
