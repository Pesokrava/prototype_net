// Package mobileconfig generates Apple .mobileconfig XML profiles
// for IKEv2 VPN with certificate authentication.
package mobileconfig

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/google/uuid"
)

//go:embed mobileconfig.xml.tmpl
var profileTemplate string

// Params holds all inputs needed to generate the .mobileconfig profile.
type Params struct {
	// ServerIP is the IKEv2 remote address.
	ServerIP string
	// ClientID is the local identifier (certificate CN).
	ClientID string
	// CAIssuerCN is the CA's Subject CN for ServerCertificateIssuerCommonName.
	CAIssuerCN string
	// CACertDER is the DER-encoded CA certificate.
	CACertDER []byte
	// PKCS12Data is the raw PKCS#12 blob.
	PKCS12Data []byte
	// PKCS12Password is the password for the PKCS#12 blob.
	PKCS12Password string
	// SyntheticPrefix is the IPv6 CIDR for split-tunnel routing (e.g. "fd00:abcd::/32").
	SyntheticPrefix string
	// ProfileName is the display name (default: "prototype-net").
	ProfileName string
}

const defaultProfileName = "prototype-net"

// templateData is the flat struct passed to the XML template.
type templateData struct {
	ProfileName         string
	ProfileUUID         string
	CAPayloadUUID       string
	IdentityPayloadUUID string
	VPNPayloadUUID      string
	ServerIP            string
	ClientID            string
	CAIssuerCN          string
	PKCS12Password      string
	CACertB64           string
	PKCS12B64           string
	RouteDestination    string
	RoutePrefixLen      int
}

// Generate creates a .mobileconfig XML file at the given path.
func Generate(path string, p *Params) error {
	if p.ProfileName == "" {
		p.ProfileName = defaultProfileName
	}

	prefixAddr, prefixLen, err := parseCIDR(p.SyntheticPrefix)
	if err != nil {
		return fmt.Errorf("parsing synthetic prefix: %w", err)
	}

	tmpl, err := template.New("mobileconfig").Parse(profileTemplate)
	if err != nil {
		return fmt.Errorf("parsing mobileconfig template: %w", err)
	}

	data := templateData{
		ProfileName:         p.ProfileName,
		ProfileUUID:         uuid.New().String(),
		CAPayloadUUID:       uuid.New().String(),
		IdentityPayloadUUID: uuid.New().String(),
		VPNPayloadUUID:      uuid.New().String(),
		ServerIP:            p.ServerIP,
		ClientID:            p.ClientID,
		CAIssuerCN:          p.CAIssuerCN,
		PKCS12Password:      p.PKCS12Password,
		CACertB64:           wrapBase64(p.CACertDER),
		PKCS12B64:           wrapBase64(p.PKCS12Data),
		RouteDestination:    prefixAddr,
		RoutePrefixLen:      prefixLen,
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("opening mobileconfig output: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("rendering mobileconfig template: %w", err)
	}

	return nil
}

// wrapBase64 encodes b as base64, wrapping at 76 characters per line.
func wrapBase64(b []byte) string {
	encoded := base64.StdEncoding.EncodeToString(b)
	var sb strings.Builder
	for len(encoded) > 76 {
		sb.WriteString(encoded[:76])
		sb.WriteByte('\n')
		encoded = encoded[76:]
	}
	if len(encoded) > 0 {
		sb.WriteString(encoded)
	}
	return sb.String()
}

// parseCIDR splits "fd00:abcd::/32" into ("fd00:abcd::", 32).
func parseCIDR(cidr string) (string, int, error) {
	for i := len(cidr) - 1; i >= 0; i-- {
		if cidr[i] == '/' {
			addr := cidr[:i]
			var prefixLen int
			_, err := fmt.Sscanf(cidr[i+1:], "%d", &prefixLen)
			if err != nil {
				return "", 0, fmt.Errorf("invalid prefix length in %q", cidr)
			}
			return addr, prefixLen, nil
		}
	}
	return "", 0, fmt.Errorf("no '/' found in CIDR %q", cidr)
}
