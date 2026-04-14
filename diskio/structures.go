// Package diskio implements basic operations for saving SKS related information
// on disk.
//
// Copyright (c) Facebook, Inc. and its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package diskio

import (
	"sync"

	"github.com/peterbourgon/diskv"
)

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
