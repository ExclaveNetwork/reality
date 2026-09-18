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

// Reference: https://github.com/XTLS/REALITY
// Reference: https://github.com/MetaCubeX/utls

//go:build go1.27 && !go1.28

package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"runtime"
	"slices"
	"sync"
	"time"
)

type realityCloseWriteConn interface {
	net.Conn
	CloseWrite() error
}

type realityMirrorConn struct {
	net.Conn
	mu     *sync.Mutex
	target net.Conn
}

func (c *realityMirrorConn) Read(b []byte) (int, error) {
	c.mu.Unlock()
	runtime.Gosched()
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	if n != 0 {
		c.target.Write(b[:n])
	}
	if err != nil {
		c.target.Close()
	}
	return n, err
}

func (c *realityMirrorConn) Write(b []byte) (int, error) {
	return 0, errors.ErrUnsupported
}

func (c *realityMirrorConn) Close() error {
	return errors.ErrUnsupported
}

func (c *realityMirrorConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *realityMirrorConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *realityMirrorConn) SetWriteDeadline(t time.Time) error {
	return nil
}

const realityRecordSize = 17 * 1024

type realityRecordType int

const (
	realityRecordTypeServerhello realityRecordType = iota
	realityRecordTypeChangeCipherSpec
	realityRecordTypeEncryptedExtensions
	realityRecordTypeCertificate
	realityRecordTypeCertificateVerify
	realityRecordTypeFinished
	realityRecordTypeNewSessionTicket
)

var realityRecordTypes = [7]realityRecordType{
	realityRecordTypeServerhello,
	realityRecordTypeChangeCipherSpec,
	realityRecordTypeEncryptedExtensions,
	realityRecordTypeCertificate,
	realityRecordTypeCertificateVerify,
	realityRecordTypeFinished,
	realityRecordTypeNewSessionTicket,
}

var (
	initED25519Priv       sync.Once
	ed25519Priv           ed25519.PrivateKey
	initSignedCert        sync.Once
	signedCert            []byte
	initSignedCertMldsa65 sync.Once
	signedCertMldsa65     []byte
)

func (hs *serverHandshakeStateTLS13) realityHandshake(authKey []byte) error {
	c := hs.c

	hs.suite = cipherSuiteTLS13ByID(hs.hello.cipherSuite)
	c.cipherSuite = hs.suite.id
	hs.transcript = hs.suite.hash.New()

	var peerData []byte
	for _, keyShare := range hs.clientHello.keyShares {
		if keyShare.group == hs.hello.serverShare.group {
			peerData = keyShare.data
			break
		}
	}

	var peerPub = peerData
	if hs.hello.serverShare.group == X25519MLKEM768 {
		peerPub = peerData[mlkem.EncapsulationKeySize768:]
	}

	key, err := generateECDHEKey(c.config.rand(), X25519)
	if err != nil {
		return err
	}
	copy(hs.hello.serverShare.data, key.PublicKey().Bytes())
	peerKey, err := key.Curve().NewPublicKey(peerPub)
	if err != nil {
		return err
	}
	hs.sharedKey, err = key.ECDH(peerKey)
	if err != nil {
		return err
	}

	if hs.hello.serverShare.group == X25519MLKEM768 {
		k, err := mlkem.NewEncapsulationKey768(peerData[:mlkem.EncapsulationKeySize768])
		if err != nil {
			return err
		}
		mlkemSharedSecret, ciphertext := k.Encapsulate()
		hs.sharedKey = append(mlkemSharedSecret, hs.sharedKey...)
		copy(hs.hello.serverShare.data, append(ciphertext, hs.hello.serverShare.data[:32]...))
	}

	c.serverName = hs.clientHello.serverName

	var cert []byte
	initED25519Priv.Do(func() {
		var err error
		_, ed25519Priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
	})
	if len(c.config.RealityServerConfig.MLDSA65Seed) > 0 {
		initSignedCertMldsa65.Do(func() {
			certificateMldsa65 := x509.Certificate{SerialNumber: &big.Int{}, ExtraExtensions: []pkix.Extension{{Id: []int{0, 0}, Value: make([]byte, 3309)}}}
			var err error
			signedCertMldsa65, err = x509.CreateCertificate(rand.Reader, &certificateMldsa65, &certificateMldsa65, ed25519.PublicKey(ed25519Priv[32:]), ed25519Priv)
			if err != nil {
				panic(err)
			}
		})
		cert = bytes.Clone(signedCertMldsa65)
	} else {
		initSignedCert.Do(func() {
			certificate := x509.Certificate{SerialNumber: &big.Int{}}
			var err error
			signedCert, err = x509.CreateCertificate(rand.Reader, &certificate, &certificate, ed25519.PublicKey(ed25519Priv[32:]), ed25519Priv)
			if err != nil {
				panic(err)
			}
		})
		cert = bytes.Clone(signedCert)
	}

	h := hmac.New(sha512.New, authKey)
	_, err = h.Write(ed25519Priv[32:])
	if err != nil {
		return err
	}
	h.Sum(cert[:len(cert)-64])

	if len(c.config.RealityServerConfig.MLDSA65Seed) > 0 {
		_, err = h.Write(hs.clientHello.original)
		if err != nil {
			return err
		}
		_, err = h.Write(hs.hello.original)
		if err != nil {
			return err
		}
		privateKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), c.config.RealityServerConfig.MLDSA65Seed)
		if err != nil {
			return err
		}
		signature, err := privateKey.SignDeterministic(h.Sum(nil), nil)
		if err != nil {
			return err
		}
		copy(cert[126:], signature)
	}

	hs.cert = &Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  ed25519Priv,
	}
	hs.sigAlg = Ed25519

	c.buffering = true
	if err := hs.sendServerParameters(true); err != nil {
		return err
	}
	if err := hs.sendServerCertificate(); err != nil {
		return err
	}
	if err := hs.sendServerFinished(); err != nil {
		return err
	}
	if hs.c.out.handshakeLen[6] != 0 {
		if _, err := c.realityWriteRecord(recordTypeHandshake, []byte{typeNewSessionTicket}); err != nil {
			return err
		}
	}
	if _, err := c.flush(); err != nil {
		return err
	}

	return nil
}

func (c *Conn) realityWriteRecord(typ recordType, data []byte) (int, error) {
	c.out.Lock()
	defer c.out.Unlock()

	if typ == recordTypeHandshake && c.out.handshakeBuf != nil &&
		len(data) > 0 && data[0] != typeServerHello {
		c.out.handshakeBuf = append(c.out.handshakeBuf, data...)
		if data[0] != typeFinished {
			return len(data), nil
		}
		data = c.out.handshakeBuf
		c.out.handshakeBuf = nil
	}

	return c.writeRecordLocked(typ, data)
}

func RealityServer(ctx context.Context, conn net.Conn, config *Config) (*Conn, error) {
	target, err := config.RealityServerConfig.DialContext(ctx)
	if err != nil {
		conn.Close()
		return nil, errors.New("REALITY: failed to dial dest: " + err.Error())
	}

	if writeProxyProtoHeader := config.RealityServerConfig.WriteProxyProtoHeader; writeProxyProtoHeader != nil {
		if _, err := writeProxyProtoHeader(conn.RemoteAddr(), conn.LocalAddr(), target); err != nil {
			target.Close()
			conn.Close()
			return nil, errors.New("REALITY: failed to send PROXY protocol: " + err.Error())
		}
	}

	underlying := conn
	if unwrapProxyProtoConn := config.RealityServerConfig.UnwrapProxyProtoConn; unwrapProxyProtoConn != nil {
		if c, ok := unwrapProxyProtoConn(conn); ok {
			underlying = c
		}
	}

	mu := new(sync.Mutex)
	var realityAuthKey []byte

	hs := serverHandshakeStateTLS13{
		c: &Conn{
			conn: &realityMirrorConn{
				Conn:   conn,
				mu:     mu,
				target: target,
			},
			config: config,
		},
		ctx: context.Background(),
	}

	copying := false

	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(2)

	go func() {
		mu.Lock()
		defer func() {
			mu.Unlock()
			if hs.c.conn != conn {
				var err error
				if ratelimit := config.RealityServerConfig.UploadRateLimit; ratelimit != nil {
					_, err = io.Copy(target, ratelimit(underlying))
				} else {
					_, err = io.Copy(target, underlying)
				}
				if err == nil {
					if closeWriteConn, ok := target.(realityCloseWriteConn); ok {
						closeWriteConn.CloseWrite()
					}
				} else {
					target.Close()
				}
			}
			waitGroup.Done()
		}()
		hs.clientHello, _, err = hs.c.readClientHello(context.Background())
		if copying || err != nil || hs.c.vers != VersionTLS13 {
			return
		}
		if _, ok := config.RealityServerConfig.ServerNames[hs.clientHello.serverName]; !ok {
			return
		}
		var peerPub []byte
		for _, keyShare := range hs.clientHello.keyShares {
			if keyShare.group == X25519 && len(keyShare.data) == 32 {
				peerPub = keyShare.data
				break
			}
		}
		if peerPub == nil {
			for _, keyShare := range hs.clientHello.keyShares {
				if keyShare.group == X25519MLKEM768 && len(keyShare.data) == mlkem.EncapsulationKeySize768+32 {
					peerPub = keyShare.data[mlkem.EncapsulationKeySize768:]
					break
				}
			}
		}
		if peerPub != nil {
			publicKey, err := ecdh.X25519().NewPublicKey(peerPub)
			if err != nil {
				return
			}
			privateKey, err := ecdh.X25519().NewPrivateKey(config.RealityServerConfig.PrivateKey)
			if err != nil {
				return
			}
			authKey, err := privateKey.ECDH(publicKey)
			if err != nil {
				return
			}
			prk, err := hkdf.Extract(sha256.New, authKey, hs.clientHello.random[:20])
			if err != nil {
				return
			}
			authKey, err = hkdf.Expand(sha256.New, prk, "REALITY", 32)
			if err != nil {
				return
			}
			realityAuthKey = authKey
			block, err := aes.NewCipher(authKey)
			if err != nil {
				return
			}
			aead, err := cipher.NewGCM(block)
			if err != nil {
				return
			}
			ciphertext := make([]byte, 32)
			plainText := make([]byte, 32)
			copy(ciphertext, hs.clientHello.sessionId)
			copy(hs.clientHello.sessionId, plainText)
			if _, err = aead.Open(plainText[:0], hs.clientHello.random[20:], ciphertext, hs.clientHello.original); err != nil {
				return
			}
			copy(hs.clientHello.sessionId, ciphertext)
			if maxTimeDiff := config.RealityServerConfig.MaxTimeDiff; maxTimeDiff != 0 {
				time := time.Unix(int64(binary.BigEndian.Uint32(plainText[4:8])), 0)
				if config.time().Sub(time).Abs() > maxTimeDiff {
					return
				}
			}
			if shortIds := config.RealityServerConfig.ShortIds; shortIds != nil {
				var shortId [8]byte
				copy(shortId[:], plainText[8:16])
				if _, ok := shortIds[shortId]; !ok {
					return
				}
			}
			hs.c.conn = conn
		}
	}()

	go func() {
		s2cSaved := make([]byte, 0, realityRecordSize)
		buf := make([]byte, realityRecordSize)
		handshakeLen := 0
	f:
		for {
			runtime.Gosched()
			n, err := target.Read(buf)
			if n == 0 {
				if err != nil {
					conn.Close()
					waitGroup.Done()
					return
				}
				continue
			}
			mu.Lock()
			s2cSaved = append(s2cSaved, buf[:n]...)
			if hs.c.conn != conn {
				copying = true
				break
			}
			if len(s2cSaved) > realityRecordSize {
				break
			}
			for _, realityRecordType := range realityRecordTypes {
				if hs.c.out.handshakeLen[realityRecordType] != 0 {
					continue
				}
				if realityRecordType == realityRecordTypeNewSessionTicket && len(s2cSaved) == 0 {
					break
				}
				if handshakeLen == 0 && len(s2cSaved) > recordHeaderLen {
					if binary.BigEndian.Uint16(s2cSaved[1:3]) != VersionTLS12 {
						break f
					}
					switch realityRecordType {
					case realityRecordTypeServerhello:
						if recordType(s2cSaved[0]) != recordTypeHandshake || s2cSaved[5] != typeServerHello {
							break f
						}
					case realityRecordTypeChangeCipherSpec:
						if recordType(s2cSaved[0]) != recordTypeChangeCipherSpec || s2cSaved[5] != typeClientHello {
							break f
						}
					default:
						if recordType(s2cSaved[0]) != recordTypeApplicationData {
							break f
						}
					}
					handshakeLen = recordHeaderLen + int(binary.BigEndian.Uint16(s2cSaved[3:5]))
				}
				if handshakeLen > realityRecordSize {
					break f
				}
				if realityRecordType == realityRecordTypeChangeCipherSpec && handshakeLen > 0 && handshakeLen != 6 {
					break f
				}
				if realityRecordType == realityRecordTypeEncryptedExtensions && handshakeLen > 512 {
					hs.c.out.handshakeLen[realityRecordType] = uint16(handshakeLen)
					hs.c.out.handshakeBuf = buf[:0]
					break
				}
				if realityRecordType == realityRecordTypeNewSessionTicket && handshakeLen > 0 {
					hs.c.out.handshakeLen[realityRecordType] = uint16(handshakeLen)
					break
				}
				if handshakeLen == 0 || len(s2cSaved) < handshakeLen {
					mu.Unlock()
					continue f
				}
				if realityRecordType == realityRecordTypeServerhello {
					hs.hello = new(serverHelloMsg)
					if !hs.hello.unmarshal(s2cSaved[recordHeaderLen:handshakeLen]) {
						break f
					}
					if hs.hello.vers != VersionTLS12 {
						break f
					}
					if hs.hello.supportedVersion != VersionTLS13 {
						break f
					}
					if cipherSuiteTLS13ByID(hs.hello.cipherSuite) == nil {
						break f
					}
					switch hs.hello.serverShare.group {
					case X25519:
						if len(hs.hello.serverShare.data) != 32 {
							break f
						}
					case X25519MLKEM768:
						if len(hs.hello.serverShare.data) != mlkem.CiphertextSize768+32 {
							break f
						}
					default:
						break f
					}
				}
				hs.c.out.handshakeLen[realityRecordType] = uint16(handshakeLen)
				s2cSaved = s2cSaved[handshakeLen:]
				handshakeLen = 0
			}
			if err = hs.realityHandshake(realityAuthKey); err != nil {
				break
			}
			go func() {
				if handshakeLen-len(s2cSaved) > 0 {
					io.ReadFull(target, buf[:handshakeLen-len(s2cSaved)])
				}
				if _, err := target.Read(buf); !hs.c.isHandshakeComplete.Load() && err != nil {
					conn.Close()
				}
			}()
			if err = hs.readClientFinished(); err != nil {
				break
			}

			if records := config.RealityServerConfig.GetPostHandshakeRecords; records != nil {
				if lengths, ok := records(hs.clientHello.alpnProtocols, hs.clientHello.serverName); ok && !slices.ContainsFunc(lengths, func(length int) bool {
					return length < 22 || length > 16389
				}) {
					for _, length := range lengths {
						plainText := make([]byte, length-16)
						plainText[0] = byte(recordTypeApplicationData)
						binary.BigEndian.PutUint16(plainText[1:3], uint16(VersionTLS12))
						binary.BigEndian.PutUint16(plainText[3:5], uint16(length - 5))
						plainText[5] = byte(recordTypeApplicationData)
						postHandshakeRecord := hs.c.out.cipher.(aead).Seal(plainText[:5], hs.c.out.seq[:], plainText[5:], plainText[:5])
						hs.c.out.incSeq()
						hs.c.write(postHandshakeRecord)
					}
				}
			}

			hs.c.isHandshakeComplete.Store(true)
			break
		}
		mu.Unlock()
		if hs.c.out.handshakeLen[0] == 0 {
			if hs.c.conn == conn {
				waitGroup.Go(func() {
					if ratelimit := config.RealityServerConfig.UploadRateLimit; ratelimit != nil {
						io.Copy(target, ratelimit(underlying))
					} else {
						io.Copy(target, underlying)
					}
				})
			}
			conn.Write(s2cSaved)
			if ratelimit := config.RealityServerConfig.DownloadRateLimit; ratelimit != nil {
				io.Copy(underlying, ratelimit(target))
			} else {
				io.Copy(underlying, target)
			}
			if closeWriteConn, ok := underlying.(realityCloseWriteConn); ok {
				closeWriteConn.CloseWrite()
			}
		}
		waitGroup.Done()
	}()

	waitGroup.Wait()
	target.Close()
	if hs.c.isHandshakeComplete.Load() {
		return hs.c, nil
	}
	conn.Close()
	return nil, errors.New("REALITY: processed invalid connection")
}

type realityListener struct {
	net.Listener
	conns chan net.Conn
	err   error
}

func (l *realityListener) Accept() (net.Conn, error) {
	if conn, ok := <-l.conns; ok {
		return conn, nil
	}
	return nil, l.err
}

func NewRealityListener(listener net.Listener, config *Config) net.Listener {
	l := &realityListener{
		Listener: listener,
		conns:    make(chan net.Conn),
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				l.err = err
				close(l.conns)
				return
			}
			go func() {
				defer func() {
					recover()
				}()
				conn, err := RealityServer(context.Background(), conn, config)
				if err == nil {
					l.conns <- conn
				}
			}()
		}
	}()
	return l
}

func RealityListen(network, laddr string, config *Config) (net.Listener, error) {
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewRealityListener(l, config), nil
}
