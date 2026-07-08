//go:build go1.26 && !go1.27

package reality

import (
	"net"

	"github.com/exclavenetwork/reality/internal/tls126"
)

type (
	AlertError                   = tls.AlertError
	Certificate                  = tls.Certificate
	CertificateRequestInfo       = tls.CertificateRequestInfo
	CertificateVerificationError = tls.CertificateVerificationError
	CipherSuite                  = tls.CipherSuite
	ClientAuthType               = tls.ClientAuthType
	ClientHelloInfo              = tls.ClientHelloInfo
	ClientSessionCache           = tls.ClientSessionCache
	ClientSessionState           = tls.ClientSessionState
	Config                       = tls.Config
	Conn                         = tls.Conn
	ConnectionState              = tls.ConnectionState
	CurveID                      = tls.CurveID
	Dialer                       = tls.Dialer
	ECHRejectionError            = tls.ECHRejectionError
	EncryptedClientHelloKey      = tls.EncryptedClientHelloKey
	QUICConfig                   = tls.QUICConfig
	QUICConn                     = tls.QUICConn
	QUICEncryptionLevel          = tls.QUICEncryptionLevel
	QUICEvent                    = tls.QUICEvent
	QUICEventKind                = tls.QUICEventKind
	QUICSessionTicketOptions     = tls.QUICSessionTicketOptions
	RecordHeaderError            = tls.RecordHeaderError
	RenegotiationSupport         = tls.RenegotiationSupport
	SessionState                 = tls.SessionState
	SignatureScheme              = tls.SignatureScheme
)

const (
	TLS_RSA_WITH_RC4_128_SHA                      = tls.TLS_RSA_WITH_RC4_128_SHA
	TLS_RSA_WITH_3DES_EDE_CBC_SHA                 = tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA
	TLS_RSA_WITH_AES_128_CBC_SHA                  = tls.TLS_RSA_WITH_AES_128_CBC_SHA
	TLS_RSA_WITH_AES_256_CBC_SHA                  = tls.TLS_RSA_WITH_AES_256_CBC_SHA
	TLS_RSA_WITH_AES_128_CBC_SHA256               = tls.TLS_RSA_WITH_AES_128_CBC_SHA256
	TLS_RSA_WITH_AES_128_GCM_SHA256               = tls.TLS_RSA_WITH_AES_128_GCM_SHA256
	TLS_RSA_WITH_AES_256_GCM_SHA384               = tls.TLS_RSA_WITH_AES_256_GCM_SHA384
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA              = tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          = tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          = tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	TLS_ECDHE_RSA_WITH_RC4_128_SHA                = tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           = tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            = tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            = tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       = tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         = tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       = tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         = tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       = tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
	TLS_AES_128_GCM_SHA256                        = tls.TLS_AES_128_GCM_SHA256
	TLS_AES_256_GCM_SHA384                        = tls.TLS_AES_256_GCM_SHA384
	TLS_CHACHA20_POLY1305_SHA256                  = tls.TLS_CHACHA20_POLY1305_SHA256
	TLS_FALLBACK_SCSV                             = tls.TLS_FALLBACK_SCSV
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305          = tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305        = tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305

	VersionTLS10 = tls.VersionTLS10
	VersionTLS11 = tls.VersionTLS11
	VersionTLS12 = tls.VersionTLS12
	VersionTLS13 = tls.VersionTLS13
	VersionSSL30 = tls.VersionSSL30

	CurveP256          = tls.CurveP256
	CurveP384          = tls.CurveP384
	CurveP521          = tls.CurveP521
	X25519             = tls.X25519
	X25519MLKEM768     = tls.X25519MLKEM768
	SecP256r1MLKEM768  = tls.SecP256r1MLKEM768
	SecP384r1MLKEM1024 = tls.SecP384r1MLKEM1024

	NoClientCert               = tls.NoClientCert
	RequestClientCert          = tls.RequestClientCert
	RequireAnyClientCert       = tls.RequireAnyClientCert
	VerifyClientCertIfGiven    = tls.VerifyClientCertIfGiven
	RequireAndVerifyClientCert = tls.RequireAndVerifyClientCert

	PKCS1WithSHA256        = tls.PKCS1WithSHA256
	PKCS1WithSHA384        = tls.PKCS1WithSHA384
	PKCS1WithSHA512        = tls.PKCS1WithSHA512
	PSSWithSHA256          = tls.PSSWithSHA256
	PSSWithSHA384          = tls.PSSWithSHA384
	PSSWithSHA512          = tls.PSSWithSHA512
	ECDSAWithP256AndSHA256 = tls.ECDSAWithP256AndSHA256
	ECDSAWithP384AndSHA384 = tls.ECDSAWithP384AndSHA384
	ECDSAWithP521AndSHA512 = tls.ECDSAWithP521AndSHA512
	Ed25519                = tls.Ed25519
	PKCS1WithSHA1          = tls.PKCS1WithSHA1
	ECDSAWithSHA1          = tls.ECDSAWithSHA1

	RenegotiateNever          = tls.RenegotiateNever
	RenegotiateOnceAsClient   = tls.RenegotiateOnceAsClient
	RenegotiateFreelyAsClient = tls.RenegotiateFreelyAsClient

	QUICEncryptionLevelInitial     = tls.QUICEncryptionLevelInitial
	QUICEncryptionLevelEarly       = tls.QUICEncryptionLevelEarly
	QUICEncryptionLevelHandshake   = tls.QUICEncryptionLevelHandshake
	QUICEncryptionLevelApplication = tls.QUICEncryptionLevelApplication

	QUICNoEvent                     = tls.QUICNoEvent
	QUICSetReadSecret               = tls.QUICSetReadSecret
	QUICSetWriteSecret              = tls.QUICSetWriteSecret
	QUICWriteData                   = tls.QUICWriteData
	QUICTransportParameters         = tls.QUICTransportParameters
	QUICTransportParametersRequired = tls.QUICTransportParametersRequired
	QUICRejectedEarlyData           = tls.QUICRejectedEarlyData
	QUICHandshakeDone               = tls.QUICHandshakeDone
	QUICResumeSession               = tls.QUICResumeSession
	QUICStoreSession                = tls.QUICStoreSession
	QUICErrorEvent                  = tls.QUICErrorEvent
)

func CipherSuites() []*CipherSuite {
	return tls.CipherSuites()
}

func CipherSuiteName(id uint16) string {
	return tls.CipherSuiteName(id)
}

func Client(conn net.Conn, config *Config) *Conn {
	return tls.Client(conn, config)
}

func Dial(network, addr string, config *Config) (*Conn, error) {
	return tls.Dial(network, addr, config)
}

func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	return tls.DialWithDialer(dialer, network, addr, config)
}

func InsecureCipherSuites() []*CipherSuite {
	return tls.InsecureCipherSuites()
}

func Listen(network, laddr string, config *Config) (net.Listener, error) {
	return tls.Listen(network, laddr, config)
}

func LoadX509KeyPair(certFile, keyFile string) (Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func NewListener(inner net.Listener, config *Config) net.Listener {
	return tls.NewListener(inner, config)
}

func NewLRUClientSessionCache(capacity int) ClientSessionCache {
	return tls.NewLRUClientSessionCache(capacity)
}

func NewResumptionState(ticket []byte, state *SessionState) (*ClientSessionState, error) {
	return tls.NewResumptionState(ticket, state)
}

func ParseSessionState(data []byte) (*SessionState, error) {
	return tls.ParseSessionState(data)
}

func QUICClient(config *QUICConfig) *QUICConn {
	return tls.QUICClient(config)
}

func QUICServer(config *QUICConfig) *QUICConn {
	return tls.QUICServer(config)
}

func Server(conn net.Conn, config *Config) *Conn {
	return tls.Server(conn, config)
}

func VersionName(version uint16) string {
	return tls.VersionName(version)
}

func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	return tls.X509KeyPair(certPEMBlock, keyPEMBlock)
}
