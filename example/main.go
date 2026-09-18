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

package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"filippo.io/mldsa"
	"github.com/exclavenetwork/reality"
)

func main() {
	nextProtos := []string{"h2", "http/1.1"}
	serverAddress, serverPort := "127.0.0.1", "8443"
	privateKey, _ := ecdh.X25519().GenerateKey(nil)
	publicKey := privateKey.PublicKey()
	var shortId [8]byte
	rand.Read(shortId[:])
	targetServerName, targetServerPort := "github.io", "443"
	mldsa65PrivateKey, _ := mldsa.GenerateKey(mldsa.MLDSA65())
	mldsa65PublicKey := mldsa65PrivateKey.PublicKey()

	go func() {
		serverConfig := &reality.Config{
			SessionTicketsDisabled: true,
			NextProtos:             nextProtos,
			RealityServerConfig: reality.RealityServerConfig{
				PrivateKey:  privateKey.Bytes(),
				MLDSA65Seed: mldsa65PrivateKey.Bytes(),
				ShortIds:    make(map[[8]byte]struct{}),
				ServerNames: make(map[string]struct{}),
				MaxTimeDiff: time.Second * 30,
				DialContext: func(ctx context.Context) (net.Conn, error) {
					return new(net.Dialer).DialContext(ctx, "tcp", net.JoinHostPort(targetServerName, targetServerPort))
				},
			},
		}
		serverConfig.RealityServerConfig.ShortIds[shortId] = struct{}{}
		serverConfig.RealityServerConfig.ServerNames[targetServerName] = struct{}{}
		listener, err := reality.RealityListen("tcp", net.JoinHostPort(serverAddress, serverPort), serverConfig)
		if err != nil {
			fmt.Println(err)
			return
		}
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		conn.Close()
		listener.Close()
	}()

	verified := false
	clientConfig := &reality.Config{
		ServerName:             targetServerName,
		NextProtos:             nextProtos,
		SessionTicketsDisabled: true,
		InsecureSkipVerify:     true,
		RealityClientConfig: reality.RealityClientConfig{
			PublicKey:     publicKey.Bytes(),
			ShortId:       shortId,
			ClientVersion: [3]byte{1, 8, 1},
		},
		VerifyConnection: func(state reality.ConnectionState) error {
			if publicKey, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey); ok {
				authKey, err := state.RealityAuthKey()
				if err != nil {
					return err
				}
				h := hmac.New(sha512.New, authKey)
				h.Write(publicKey)
				if bytes.Equal(h.Sum(nil), state.PeerCertificates[0].Signature) {
					if mldsa65PublicKey != nil {
						if len(state.PeerCertificates[0].Extensions) > 0 {
							clientHello, err := state.RawClientHello()
							if err != nil {
								return err
							}
							serverHello, err := state.RawServerHello()
							if err != nil {
								return err
							}
							h.Write(clientHello)
							h.Write(serverHello)
							if err := mldsa.Verify(mldsa65PublicKey, h.Sum(nil), state.PeerCertificates[0].Extensions[0].Value, nil); err != nil {
								return err
							}
							verified = true
							return nil
						}
					} else {
						verified = true
						return nil
					}
				}
			}
			opts := x509.VerifyOptions{
				DNSName:       targetServerName,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range state.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			if _, err := state.PeerCertificates[0].Verify(opts); err != nil {
				return err
			}
			return nil
		},
	}
	if disablePQ := false; disablePQ {
		clientConfig.CurvePreferences = []reality.CurveID{reality.X25519, reality.CurveP256, reality.CurveP384, reality.CurveP521}
	}
	conn, err := reality.Dial("tcp", net.JoinHostPort(serverAddress, serverPort), clientConfig)
	if err != nil {
		fmt.Println(err)
		return
	}
	conn.Close()
	if verified {
		fmt.Println("success")
	} else {
		fmt.Println("genuine certificate received")
	}
}
