// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package riscv64cpu

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	HWPROBE_KEY_IMA_EXT_0 = 0x4
	HWPROBE_KEY_CPUPERF_0 = 0x5
	HWPROBE_EXT_ZVKNED    = 0x200000

	sys_HWPROBE = 258
)

func init() {
	pairs := []hwProbePairs{
		{key: HWPROBE_KEY_IMA_EXT_0, value: 0},
		{key: HWPROBE_KEY_CPUPERF_0, value: 0},
	}
	if hwProbe(pairs, 0) {
		if pairs[0].key != -1 {
			v := uint(pairs[0].value)
			HasZvkned = isSet(v, HWPROBE_EXT_ZVKNED)
		}
	}
	env := os.Getenv("GODEBUG")
field:
	for env != "" {
		field := ""
		i := strings.IndexByte(env, ',')
		if i < 0 {
			field, env = env, ""
		} else {
			field, env = env[:i], env[i+1:]
		}
		if len(field) < 4 || field[:4] != "cpu." {
			continue
		}
		i = strings.IndexByte(field, '=')
		if i < 0 {
			continue
		}
		key, value := field[4:i], field[i+1:]
		var enable bool
		switch value {
		case "on":
			enable = true
		case "off":
			enable = false
		default:
			continue field
		}
		if key == "all" || key == "zvkned" {
			HasZvkned = enable
			continue
		}
	}
}

var HasZvkned = false

type hwProbePairs struct {
	key   int64
	value uint64
}

func isSet(hwc uint, value uint) bool {
	return hwc&value != 0
}

func hwProbe(pairs []hwProbePairs, flags uint) bool {
	p0 := unsafe.Pointer(&pairs[0])
	_, _, e1 := syscall.Syscall6(sys_HWPROBE, uintptr(p0), uintptr(len(pairs)), uintptr(0), uintptr(0), uintptr(flags), 0)
	return e1 == 0
}
