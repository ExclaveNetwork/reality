// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.26 && !go1.27

package tls

var _ = &Config{WrapSession: (&Config{}).EncryptTicket}
var _ = &Config{UnwrapSession: (&Config{}).DecryptTicket}
