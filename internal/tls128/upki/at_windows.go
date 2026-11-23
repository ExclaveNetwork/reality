// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.28 && windows

package upki

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const O_DIRECTORY = 0x04000

func initObjectAttributes(o *windows.OBJECT_ATTRIBUTES, root windows.Handle, name string) error {
	if name == "." {
		name = ""
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return err
	}
	o.ObjectName = objectName
	if root != windows.InvalidHandle {
		o.RootDirectory = root
	}
	o.Length = uint32(unsafe.Sizeof(*o))
	return nil
}

func openat(dirfd windows.Handle, name string) (windows.Handle, error) {
	if len(name) == 0 {
		return windows.InvalidHandle, syscall.ERROR_FILE_NOT_FOUND
	}
	var access, options uint32
	access |= windows.FILE_GENERIC_READ
	access |= windows.STANDARD_RIGHTS_READ | windows.FILE_READ_ATTRIBUTES | windows.FILE_READ_EA
	objAttrs := &windows.OBJECT_ATTRIBUTES{}
	if err := initObjectAttributes(objAttrs, dirfd, name); err != nil {
		return windows.InvalidHandle, err
	}
	var h windows.Handle
	err := windows.NtCreateFile(
		&h,
		windows.SYNCHRONIZE|access,
		objAttrs,
		&windows.IO_STATUS_BLOCK{},
		nil,
		uint32(windows.FILE_ATTRIBUTE_READONLY),
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		uint32(windows.FILE_OPEN),
		windows.FILE_OPEN_FOR_BACKUP_INTENT|options,
		uintptr(unsafe.Pointer(nil)),
		0,
	)
	if err != nil {
		return h, ntCreateFileError(err)
	}
	return h, nil
}

func ntCreateFileError(err error) error {
	s, ok := err.(windows.NTStatus)
	if !ok {
		return err
	}
	switch s {
	case windows.STATUS_REPARSE_POINT_ENCOUNTERED:
		return syscall.ELOOP
	case windows.STATUS_NOT_A_DIRECTORY:
	case windows.STATUS_FILE_IS_A_DIRECTORY:
		return syscall.EISDIR
	case windows.STATUS_OBJECT_NAME_COLLISION:
		return syscall.EEXIST
	}
	return s.Errno()
}
