// Copyright (c) Meta Platforms, Inc. and affiliates.
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

package sks

import (
	"bytes"
	"testing"
)

func TestWithAuthValue(t *testing.T) {
	want := []byte("secret-pin")
	k := &regularKey{}
	WithAuthValue(want)(k)
	if !bytes.Equal(k.authValue, want) {
		t.Errorf("WithAuthValue set authValue = %q, want %q", k.authValue, want)
	}
}

func TestFromLabelTagAuthValue(t *testing.T) {
	want := []byte("secret-pin")
	k, ok := FromLabelTag("label:tag", WithAuthValue(want)).(*regularKey)
	if !ok {
		t.Fatal("FromLabelTag did not return a *regularKey")
	}
	if k.label != "label" || k.tag != "tag" {
		t.Errorf("FromLabelTag parsed label=%q tag=%q, want label and tag", k.label, k.tag)
	}
	if !bytes.Equal(k.authValue, want) {
		t.Errorf("FromLabelTag authValue = %q, want %q", k.authValue, want)
	}
}

func TestFromLabelTagNoAuthValue(t *testing.T) {
	if k := FromLabelTag("label:tag").(*regularKey); k.authValue != nil {
		t.Errorf("FromLabelTag without options set authValue = %q, want nil", k.authValue)
	}
}
