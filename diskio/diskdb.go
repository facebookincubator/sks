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

package diskio

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"sync"

	"github.com/jgoguen/go-utils/xdg"
	"github.com/peterbourgon/diskv"
)

var (
	db   Database
	once sync.Once
)

// This file contains functions for working with the simple on-disk key/value
// store.

func (diskdb *diskKVStore) Load(key string) ([]byte, error) {
	diskdb.mux.RLock()
	defer diskdb.mux.RUnlock()

	return diskdb.db.Read(key)
}

func (diskdb *diskKVStore) Save(key string, value []byte) (string, error) {
	var savedKey string
	if key != "" {
		savedKey = key
	} else {
		sum := sha256.Sum256(value)
		savedKey = hex.EncodeToString(sum[:])
	}

	diskdb.mux.Lock()
	defer diskdb.mux.Unlock()

	err := diskdb.db.Write(savedKey, value)

	return savedKey, err
}

func (diskdb *diskKVStore) HasKey(key string) bool {
	diskdb.mux.RLock()
	defer diskdb.mux.RUnlock()

	return diskdb.db.Has(key)
}

func (diskdb *diskKVStore) Delete(key string) error {
	diskdb.mux.Lock()
	defer diskdb.mux.Unlock()

	return diskdb.db.Erase(key)
}

func (diskdb *diskKVStore) List() ([]string, error) {
	var keys []string

	diskdb.mux.RLock()
	defer diskdb.mux.RUnlock()

	for v := range diskdb.db.Keys(nil) {
		keys = append(keys, v)
	}

	return keys, nil
}

func (diskdb *diskKVStore) Visit(visitor func(key string, val []byte) error) error {
	diskdb.mux.RLock()
	defer diskdb.mux.RUnlock()

	cancel := make(chan struct{})
	defer close(cancel)

	for key := range diskdb.db.Keys(cancel) {
		val, err := diskdb.db.Read(key)
		if err != nil {
			return err
		}
		if err := visitor(key, val); err != nil {
			return err
		}
	}

	return nil
}

// OpenDB opens a Database connection.
func OpenDB() (Database, error) {
	var err error

	once.Do(func() {
		dbDir := xdg.GetDataPath("sks")
		if dbDir == "" {
			err = errors.New("could not determine the location for the DB")
		}

		err = os.MkdirAll(dbDir, 0700)
		if err != nil {
			return
		}

		db = &diskKVStore{
			db: diskv.New(diskv.Options{
				BasePath:     dbDir,
				CacheSizeMax: 1024 * 1024, // 1MB cache max
				FilePerm:     0600,
				PathPerm:     0700,
			}),
		}
	})

	return db, err
}
