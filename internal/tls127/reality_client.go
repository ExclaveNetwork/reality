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

//go:build go1.27 && !go1.28

package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

func (c *Config) makeRealityClientHello(hello *clientHelloMsg, keys *keySharePrivateKeys) error {
	if keys.ecdhe == nil {
		return errors.New("nil ecdhe")
	}
	publicKey, err := ecdh.X25519().NewPublicKey(c.RealityClientConfig.PublicKey)
	if err != nil {
		return err
	}
	authKey, err := keys.ecdhe.ECDH(publicKey)
	if err != nil {
		return err
	}
	prk, err := hkdf.Extract(sha256.New, authKey, hello.random[:20])
	if err != nil {
		return err
	}
	authKey, err = hkdf.Expand(sha256.New, prk, "REALITY", 32)
	if err != nil {
		return err
	}
	hello.sessionId = make([]byte, 32)
	original, err := hello.marshal()
	if err != nil {
		return err
	}
	auth := make([]byte, 16)
	copy(auth[0:3], c.RealityClientConfig.ClientVersion[:])
	binary.BigEndian.PutUint32(auth[4:8], uint32(c.time().Unix()))
	copy(auth[8:16], c.RealityClientConfig.ShortId[:])
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	hello.sessionId = aead.Seal(auth[:0], hello.random[20:], auth[:16], original)
	hello.realityAuthKey = authKey
	original, err = hello.marshal()
	if err != nil {
		return err
	}
	hello.original = original
	return nil
}
