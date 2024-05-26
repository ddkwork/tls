// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Most functionality in this package is tested by replacing existing code
// and inheriting that code's tests.

package boring

import (
	"testing"

	"github.com/ddkwork/golibrary/mylog"
)

// Test that func init does not panic.
func TestInit(t *testing.T) {}

// Test that Unreachable panics.
func TestUnreachable(t *testing.T) {
	defer func() { mylog.Check(recover()) }()
	Unreachable()
}

// Test that UnreachableExceptTests does not panic (this is a test).
func TestUnreachableExceptTests(t *testing.T) {
	UnreachableExceptTests()
}
