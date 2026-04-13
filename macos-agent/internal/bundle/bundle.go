// Package bundle parses and validates client bundle JSON files
// produced by certs/gen-client.sh.
package bundle

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

// Bundle represents the JSON structure emitted by certs/gen-client.sh.
type Bundle struct {
	CACertPEM     string `json:"ca_cert_pem"`
	ClientCertPEM string `json:"client_cert_pem"`
	ClientKeyPEM  string `json:"client_key_pem"`
	ClientID      string `json:"client_id"`
	// PKCS12B64 is the base64-encoded PKCS#12 blob pre-generated with
	// OpenSSL 3.x -legacy. Present in bundles generated after the P12
	// pre-generation change; empty for older bundles.
	PKCS12B64 string `json:"pkcs12_b64,omitempty"`
	// PKCS12Password is the password for the pre-generated PKCS#12 blob.
	PKCS12Password string `json:"pkcs12_password,omitempty"`
}

// Load reads and validates a client bundle from path.
// It verifies that all four fields are present and that the PEM data
// is parseable.
func Load(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading bundle file: %w", err)
	}

	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing bundle JSON: %w", err)
	}

	if b.CACertPEM == "" {
		return nil, fmt.Errorf("bundle missing ca_cert_pem")
	}
	if b.ClientCertPEM == "" {
		return nil, fmt.Errorf("bundle missing client_cert_pem")
	}
	if b.ClientKeyPEM == "" {
		return nil, fmt.Errorf("bundle missing client_key_pem")
	}
	if b.ClientID == "" {
		return nil, fmt.Errorf("bundle missing client_id")
	}

	// Verify PEM is parseable.
	if _, err := b.ParseCACert(); err != nil {
		return nil, fmt.Errorf("invalid ca_cert_pem: %w", err)
	}
	if block, _ := pem.Decode([]byte(b.ClientCertPEM)); block == nil {
		return nil, fmt.Errorf("client_cert_pem: no valid PEM block found")
	}
	if block, _ := pem.Decode([]byte(b.ClientKeyPEM)); block == nil {
		return nil, fmt.Errorf("client_key_pem: no valid PEM block found")
	}

	return &b, nil
}

// ParseCACert parses the CA certificate PEM and returns the x509 certificate.
func (b *Bundle) ParseCACert() (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(b.CACertPEM))
	if block == nil {
		return nil, fmt.Errorf("no valid PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing X.509 certificate: %w", err)
	}
	return cert, nil
}

// CAIssuerCN extracts the issuer Common Name from the CA certificate.
func (b *Bundle) CAIssuerCN() (string, error) {
	cert, err := b.ParseCACert()
	if err != nil {
		return "", err
	}
	// For a self-signed CA, Subject.CN == Issuer.CN.
	// We use the Subject CN since that's the CA's identity that gets
	// referenced in ServerCertificateIssuerCommonName.
	cn := cert.Subject.CommonName
	if cn == "" {
		return "", fmt.Errorf("CA certificate has empty Subject CN")
	}
	return cn, nil
}

// HasPKCS12 returns true if the bundle contains a pre-generated PKCS#12 blob.
func (b *Bundle) HasPKCS12() bool {
	return b.PKCS12B64 != "" && b.PKCS12Password != ""
}

// DecodePKCS12 decodes the base64-encoded PKCS#12 blob.
// Returns an error if the bundle doesn't contain a P12 blob.
func (b *Bundle) DecodePKCS12() ([]byte, error) {
	if !b.HasPKCS12() {
		return nil, fmt.Errorf("bundle does not contain pre-generated PKCS#12")
	}
	data, err := base64.StdEncoding.DecodeString(b.PKCS12B64)
	if err != nil {
		return nil, fmt.Errorf("decoding pkcs12_b64: %w", err)
	}
	return data, nil
}
