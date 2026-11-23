// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.28 && windows

package upki

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func readFilterFile(path string) ([]byte, error) {
	f, err := openCacheFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// windows.Openat shares delete access so a cache producer can replace the
// index or remove an obsolete filter while a check is reading it.
func openCacheFile(path string) (*os.File, error) {
	parent, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer parent.Close()

	handle, err := openat(windows.Handle(parent.Fd()), filepath.Base(path))
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	return os.NewFile(uintptr(handle), path), nil
}
