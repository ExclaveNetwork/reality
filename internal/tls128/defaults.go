// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.28

package tls

import (
	"os"
	"slices"
	"sync"
	_ "unsafe" // for linkname
)

var (
	TLSSHA1       = ""
	TLSMLKEM      = ""
	TLSSecpMLKEM  = ""
	TLSMaxRSASize = ""
)

var godebug = &godebugStruct{
	kv: make(map[string]string),
}

type godebugStruct struct {
	once sync.Once
	kv   map[string]string
}

func (d *godebugStruct) value(key string) string {
	d.once.Do(func() {
		s := os.Getenv("GODEBUG")
		end := len(s)
		eq := -1
		for i := end - 1; i >= -1; i-- {
			if i == -1 || s[i] == ',' {
				if eq >= 0 {
					k, v := s[i+1:eq], s[eq+1:end]
					if _, ok := d.kv[k]; !ok {
						for j := 0; j < len(v); j++ {
							if v[j] == '#' {
								v = v[:j]
								break
							}
						}
						d.kv[k] = v
					}
				}
				eq = -1
				end = i
			} else if s[i] == '=' {
				eq = i
			}
		}
		if _, ok := d.kv["tlssha1"]; !ok {
			d.kv["tlssha1"] = TLSSHA1
		}
		if _, ok := d.kv["tlsmlkem"]; !ok {
			d.kv["tlsmlkem"] = TLSMLKEM
		}
		if _, ok := d.kv["tlssecpmlkem"]; !ok {
			d.kv["tlssecpmlkem"] = TLSSecpMLKEM
		}
		if _, ok := d.kv["tlsmaxrsasize"]; !ok {
			d.kv["tlsmaxrsasize"] = TLSMaxRSASize
		}
	})
	return d.kv[key]
}

// Defaults are collected in this file to allow distributions to more easily patch
// them to apply local policies.

// defaultCurveEnabled returns whether the key exchange c is enabled by default.
func defaultCurveEnabled(c CurveID) bool {
	switch c {
	case X25519, CurveP256, CurveP384, CurveP521:
		return true
	case X25519MLKEM768:
		return godebug.value("tlsmlkem") != "0"
	case SecP256r1MLKEM768, SecP384r1MLKEM1024:
		return godebug.value("tlsmlkem") != "0" && godebug.value("tlssecpmlkem") != "0"
	default:
		return false
	}
}

// curvePreferenceOrder is the fixed preference order of key exchanges. It must
// include every supported key exchange.
func curvePreferenceOrder() []CurveID {
	return []CurveID{
		X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, MLKEM1024,
		X25519, CurveP256, CurveP384, CurveP521,
	}
}

// defaultSupportedSignatureAlgorithms returns the signature and hash algorithms that
// the code advertises and supports in a TLS 1.2+ ClientHello and in a TLS 1.2+
// CertificateRequest. The two fields are merged to match with TLS 1.3.
// Note that in TLS 1.2, the ECDSA algorithms are not constrained to P-256, etc.
func defaultSupportedSignatureAlgorithms() []SignatureScheme {
	return []SignatureScheme{
		MLDSA44,
		MLDSA65,
		MLDSA87,
		PSSWithSHA256,
		ECDSAWithP256AndSHA256,
		Ed25519,
		PSSWithSHA384,
		PSSWithSHA512,
		PKCS1WithSHA256,
		PKCS1WithSHA384,
		PKCS1WithSHA512,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512,
		PKCS1WithSHA1,
		ECDSAWithSHA1,
	}
}

func supportedCipherSuites(aesGCMPreferred bool) []uint16 {
	if aesGCMPreferred {
		return slices.Clone(cipherSuitesPreferenceOrder)
	} else {
		return slices.Clone(cipherSuitesPreferenceOrderNoAES)
	}
}

func defaultCipherSuites(aesGCMPreferred bool) []uint16 {
	cipherSuites := supportedCipherSuites(aesGCMPreferred)
	return slices.DeleteFunc(cipherSuites, func(c uint16) bool {
		return disabledCipherSuites[c]
	})
}

// defaultCipherSuitesTLS13 is also the preference order, since there are no
// disabled by default TLS 1.3 cipher suites. The same AES vs ChaCha20 logic as
// cipherSuitesPreferenceOrder applies.
//
// defaultCipherSuitesTLS13 should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/quic-go/quic-go
//   - github.com/sagernet/quic-go
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname defaultCipherSuitesTLS13
var defaultCipherSuitesTLS13 = []uint16{
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_CHACHA20_POLY1305_SHA256,
}

// defaultCipherSuitesTLS13NoAES should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/quic-go/quic-go
//   - github.com/sagernet/quic-go
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname defaultCipherSuitesTLS13NoAES
var defaultCipherSuitesTLS13NoAES = []uint16{
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
}
