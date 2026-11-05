// Copyright 2026 dyhkwong
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package godebug

import (
	"os"
	"runtime/debug"
	"sync"
)

var (
	once           sync.Once
	envGoDebug     map[string]string
	defaultGoDebug map[string]string
)

func parse(str string) map[string]string {
	end := len(str)
	eq := -1
	kv := make(map[string]string)
	for i := end - 1; i >= -1; i-- {
		if i == -1 || str[i] == ',' {
			if eq >= 0 {
				key, value := str[i+1:eq], str[eq+1:end]
				if _, ok := kv[key]; !ok {
					for j := 0; j < len(value); j++ {
						if value[j] == '#' {
							value = value[:j]
							break
						}
					}
					kv[key] = value
				}
			}
			eq = -1
			end = i
		} else if str[i] == '=' {
			eq = i
		}
	}
	return kv
}

func Value(key string) string {
	once.Do(func() {
		if env := os.Getenv("GODEBUG"); len(env) > 0 {
			envGoDebug = parse(env)
		}
		if len(godebugDefault) > 0 {
			defaultGoDebug = parse(godebugDefault)
		} else if buildInfo, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range buildInfo.Settings {
				if setting.Key == "DefaultGODEBUG" {
					defaultGoDebug = parse(setting.Value)
					break
				}
			}
		}
	})
	if value, ok := envGoDebug[key]; ok {
		return value
	}
	if value, ok := defaultGoDebug[key]; ok {
		return value
	}
	return ""
}
