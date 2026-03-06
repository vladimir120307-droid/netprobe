package http

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// TLSInfo holds extracted TLS certificate and connection details.
type TLSInfo struct {
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	DaysLeft    int      `json:"days_left"`
	SANs        []string `json:"sans"`
	Protocol    string   `json:"protocol"`
	CipherSuite string   `json:"cipher_suite"`
	SerialNum   string   `json:"serial_number"`
	SignAlgo    string   `json:"signature_algorithm"`
	IsExpired   bool     `json:"is_expired"`
}

// ExtractTLSInfo extracts certificate and connection information from a
// TLS connection state. This includes subject, issuer, validity period,
// SANs, protocol version, and cipher suite details.
func ExtractTLSInfo(state *tls.ConnectionState) *TLSInfo {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}

	cert := state.PeerCertificates[0]

	info := &TLSInfo{
		Subject:     cert.Subject.CommonName,
		Issuer:      FormatIssuerFromCert(cert),
		NotBefore:   cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:    cert.NotAfter.UTC().Format(time.RFC3339),
		DaysLeft:    int(time.Until(cert.NotAfter).Hours() / 24),
		SANs:        extractSANs(cert),
		Protocol:    tlsVersionString(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		SerialNum:   fmt.Sprintf("%x", cert.SerialNumber),
		SignAlgo:    cert.SignatureAlgorithm.String(),
		IsExpired:   time.Now().After(cert.NotAfter),
	}

	return info
}

// FormatIssuerFromCert builds a formatted issuer string from a certificate.
func FormatIssuerFromCert(cert *x509.Certificate) string {
	var parts []string

	if len(cert.Issuer.Organization) > 0 {
		parts = append(parts, cert.Issuer.Organization[0])
	}
	if cert.Issuer.CommonName != "" {
		parts = append(parts, cert.Issuer.CommonName)
	}
	if len(cert.Issuer.Country) > 0 {
		parts = append(parts, cert.Issuer.Country[0])
	}

	if len(parts) == 0 {
		return "Unknown"
	}
	return strings.Join(parts, ", ")
}

// extractSANs retrieves all Subject Alternative Names from a certificate,
// including DNS names and IP addresses.
func extractSANs(cert *x509.Certificate) []string {
	var sans []string

	for _, name := range cert.DNSNames {
		sans = append(sans, name)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, email := range cert.EmailAddresses {
		sans = append(sans, email)
	}
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}

	return sans
}

// tlsVersionString converts a TLS version constant to its human-readable name.
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// CertExpiryStatus returns a human-readable status string for certificate expiry.
func CertExpiryStatus(daysLeft int) string {
	switch {
	case daysLeft < 0:
		return fmt.Sprintf("EXPIRED (%d days ago)", -daysLeft)
	case daysLeft == 0:
		return "EXPIRES TODAY"
	case daysLeft <= 7:
		return fmt.Sprintf("CRITICAL (%d days left)", daysLeft)
	case daysLeft <= 30:
		return fmt.Sprintf("WARNING (%d days left)", daysLeft)
	case daysLeft <= 90:
		return fmt.Sprintf("OK (%d days left)", daysLeft)
	default:
		return fmt.Sprintf("VALID (%d days left)", daysLeft)
	}
}

// CheckTLSCert connects to a host and checks its TLS certificate. Useful for
// standalone certificate validation without performing a full HTTP request.
func CheckTLSCert(host string, port int, timeout time.Duration) (*TLSInfo, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		addr,
		&tls.Config{
			InsecureSkipVerify: false,
			ServerName:         host,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	return ExtractTLSInfo(&state), nil
}

// VerifyCertChain validates the full certificate chain presented by the server.
// Returns nil if the chain is valid, or an error describing the problem.
func VerifyCertChain(state *tls.ConnectionState) error {
	if state == nil || len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no certificates presented")
	}

	opts := x509.VerifyOptions{
		CurrentTime:   time.Now(),
		Intermediates: x509.NewCertPool(),
	}

	for _, cert := range state.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}

	_, err := state.PeerCertificates[0].Verify(opts)
	return err
}
