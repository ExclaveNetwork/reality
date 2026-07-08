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
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"

	"filippo.io/mldsa"
	"github.com/exclavenetwork/reality"
	"golang.org/x/net/http2"
)

func main() {
	publicKey, _ := base64.RawURLEncoding.DecodeString("p7FrZ-otK4A-bCUnnSunNcv5V8BcgX2KCO0jng4CoE0")
	var shortId [8]byte
	_, _ = hex.Decode(shortId[:], []byte("0123456789abcdef"))
	mldsa65Verify, _ := base64.RawURLEncoding.DecodeString("BCmCreqlLcf3taIRW799tGXhE94xFuO3BQks_g-iXYiqIIjY_3m66zd_GyjVAMDZe0sVwqQmOJoAe7jyU1G3kRD3RWg4j0iQGzvyGNGIfDlGvIcPuWCr3s1v1gpS62fxgdYs4G_znaMv7cgkcbewNTyisneMOrdINv2qfqmhpn16NU2YcjJaB7j5pAfvskKUrnr5dw8e8XkIbLuuzM9WT317tujw3S_S60mlU7Te_KRXFZGih_x4uXc-hW_tfnrt-lKwn8v-NlRlnJatp6CCROsqMowqYF8x46r9wZfuY9CBZoX0NP3o0eyNDMFds2U5as1-NsQTio2peSndbZm32adcAf2CgK85rjj5vOo270olMo_POJhtGhbfNmKuQVL6YJEcCXueGtNwea9CFvE-B2wOYsi7Y8adTJBz_aGIN237mqvDuatj-PeGO-43BrDIBvvZrSQSNOV2Plhb0zMrpiXw4a9tcobOJJdtmLjn_KPT93eycYKlsTGxNwtmhFeq7-0vKKZMmoOswOAzDDDgQ9xEWmpqisth7hkjeIcCXjLe53umTAzpR78Y83eJTbgf-tnrMms5daNSwwxM_EOJZgvqAALUwjGkU581s_UmX_ouDj-5M4tAUif_2j_99ijF1T-uTjaOgac2_gFGBzaVHfNGvnKU0Xv1PmWyAUyAxsIuSmgmCWh5feq_wtrceSo1EocFoBFqpJ3wjrkX-yTBrJ2sVIhrpDx96jg32RPjGkkASw_L7vuqmj8aOSKXMl3anWGYSbnl5rbyxPTyOSctH0Tc1Q5cK-OrKaWqkZ1G3XuXv5s21-xrLrS-0MjFhhiZY7nT6wPpZAAWmVImOCN8rOv5tNUOhNeAe3EYgw85TQajN1DjHLbf7Ep-_l0lcp-0RwNOPiS_QQLfjnS1x-4OqJWoCZUKx-B4KrcNAxFIsCPgcSRSRgZErqUD6NZfXNImDKf7PBCk2QUHeHuDqTj-vrEahF9292AK5NWYX22j3JK-x6dadP9Biv5gnwFmugoAQDKd7iip-hvHhzLViqMzyrD9Ohfs220WuO4Y4mzLgUJC4tnOSH5MOchlqP7Xsn9ga-ZQ2-pTcEgNgdoQvcqFq--jwGz_4_GAGhkl-1f8hcxF-K3AmTPJwCS5zWRHIoMI-mEnggSxoZ3HruE-SfCTnzxe9ZDUH7gNIzxMMDt9ZFk6ARSaKwwqyI0OBn7t0-6KG2PSbVDFNN_A1Q11vCvVnM1JgYnSv5HuNldTM7EfRG8KhlzB1FBJChG-d3SMOH26ZJuOBD4y2W-eDrKnqm7I51E2nZRgSUAKLfpVvsqsFbmO_DO0eitjMf-FFfzdtKpARaNClPy6wDedIDTni3bKTVNSLMHpHJ6MqU6kp9pSn1TiiLkFn1T1FUEQe1yPaP_C6GWbxmm3Qg2418gmit_Kz7eN6WZoQRbZQo0xOS9ooyhcF-mEU9zhY0EwInlw7EhS1MQMlyCUe1ph9W6YwDeBHcFHT4z6Hw3qy8t40ib8EqsLhtgwfIhVZhWXInnJJPabTJQbkCRfuOeHMmH_aslOXlWIZ4Yz1Y4DibRK5aIVTEtfRxWyEFm9gri3A2basKphnl2sIlCJL8FLrk5cev3gp_T0RSDCwB6n6_FUVrNdSfLqbBObDOUBrdO5K8JktnwgbsFiy79_zRQm4XWyQ-3ywNSS5sCTSv1Qz3MDms0P7jqcPZxmW19wVMurvECBYzhEUszPeD52FRgg9tK0ONSPanSiAm5zfFtehLD374h8EZtRBkZnG1b181UWKT-tuMz3iJUtdz85wzicwR-OLXhuJz2vXwnhqJjiyHRoD0tOgKZIrcy5tksswli8dz1BHBwYn0t-Z-ymYcXU_HiBJseWkL-KhmlWHNofZNbj0egOLVkDrbhbxce-SngbfP4TKFfmHfPhecJCdnbbGkqo3Jf2jLlh2bNQjO4nlneDeB2p9PzQI1O9URUtfkLTOkO6oQvEev69ZxDtdljCP-iZWbhQFgbVjEOfZl6aN5RBET5n-UESd_fbH1-ba4Wdw0xMtfyIXm0V9FP0XANEiOg6-CkQvRdVo1vzCd_5kywcLxKRJZpXMM-fIBHHSUv0D-BigxWrBcbMr4D8c8SxenOA8b5FshtSBV1C_P2LYThvT5aMBTj60nocQlTcyAUdwVUp1LVZhVqmS6rMJiiOh3hCbS6OLcEvS4hJXxu5g03hV7Kxk6sTX7Lfbhut9RWyVI0crDBRSFgsI9vP2fSZtMadnT9KWVGeMaAFrttzOrc3q2E47zAkmt8oV72ufvAQ4SDVdX3ENuCOyFY5qOAPdkQs16RrB5JpaC541zwYPvXCz0NJ8ApIVG3Ofo-5O5tGEJgNn6Ns54gkDbl-D9HRcwrVW6iy2xyxXbskE7VQVbRM8ZKkMJoT3xPO1OwPtqLiSdEOSeJsJy_Tw2sa-rL8u7DTKTK9XPBlzHXWFlmAE8Pzt-IX-_GarFJZjdNKcPC3pWBB2e09xBNggQH4hmyRBQgLRXdkohDzB8wNA9kz6CvYtFqgsBpyBCxP5Uy-ENYU1Qokv5AipLo1mtXmsVqiW59exLjY7wD5v6sGDpzdI-HI8wOoqAo")
	mldsaPublicKey, _ := mldsa.NewPublicKey(mldsa.MLDSA65(), mldsa65Verify)
	serverName := "example.com"
	verified := false
	config := &reality.Config{
		RealityPublicKey:       publicKey,
		RealityShortId:         shortId,
		RealityClientVersion:   [3]byte{1, 8, 1},
		NextProtos:             []string{"h2", "http/1.1"},
		ServerName:             serverName,
		SessionTicketsDisabled: true,
		InsecureSkipVerify:     true,
		VerifyConnection: func(state reality.ConnectionState) error {
			if publicKey, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey); ok {
				authKey, err := state.RealityAuthKey()
				if err != nil {
					return err
				}
				h := hmac.New(sha512.New, authKey)
				h.Write(publicKey)
				if bytes.Equal(h.Sum(nil), state.PeerCertificates[0].Signature) {
					if mldsaPublicKey != nil {
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
							if err := mldsa.Verify(mldsaPublicKey, h.Sum(nil), state.PeerCertificates[0].Extensions[0].Value, nil); err != nil {
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
				DNSName:       serverName,
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
	disablePQ := false
	if disablePQ {
		config.CurvePreferences = []reality.CurveID{reality.X25519, reality.CurveP256, reality.CurveP384, reality.CurveP521}
	}
	conn, err := net.Dial("tcp", "127.0.0.1:443")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	realityConn := reality.Client(conn, config)
	if err := realityConn.Handshake(); err != nil {
		fmt.Println(err)
		return
	}
	if !verified {
		fmt.Println("genuine certificate received")
		client := &http.Client{
			Transport: &http2.Transport{
				DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					return realityConn, nil
				},
			},
		}
		req, err := http.NewRequest("GET", "https://"+serverName, nil)
		if err != nil {
			fmt.Println(err)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return
	}
	fmt.Println("success")
}
