// Package pkcs12 generates PKCS#12 files from PEM-encoded cert+key
// using the openssl CLI. The .p12 is created with a random ephemeral
// password and cleaned up via the returned cleanup function.
package pkcs12

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Result contains the path and password of the generated PKCS#12 file.
type Result struct {
	Path     string
	Password string
}

// Generate creates a temporary PKCS#12 file from PEM-encoded client cert,
// client key, and CA cert. Returns the result and a cleanup function that
// should be deferred to remove the temporary files.
//
// The PKCS#12 password is a random hex string that is never persisted.
func Generate(clientCertPEM, clientKeyPEM, caCertPEM string) (*Result, func(), error) {
	tmpDir, err := os.MkdirTemp("", "prototype-net-p12-*")
	if err != nil {
		return nil, nil, fmt.Errorf("creating temp dir: %w", err)
	}

	cleanup := func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to clean up temp dir %s: %v\n", tmpDir, err)
		}
	}

	certPath := filepath.Join(tmpDir, "client.crt")
	keyPath := filepath.Join(tmpDir, "client.key")
	caPath := filepath.Join(tmpDir, "ca.crt")
	p12Path := filepath.Join(tmpDir, "client.p12")

	if err := os.WriteFile(certPath, []byte(clientCertPEM), 0o600); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("writing client cert: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(clientKeyPEM), 0o600); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("writing client key: %w", err)
	}
	if err := os.WriteFile(caPath, []byte(caCertPEM), 0o600); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("writing CA cert: %w", err)
	}

	// Generate random ephemeral password.
	pwBytes := make([]byte, 16)
	if _, err := rand.Read(pwBytes); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("generating random password: %w", err)
	}
	password := hex.EncodeToString(pwBytes)

	// Use openssl to create the PKCS#12 bundle.
	// -legacy flag ensures compatibility with macOS Keychain import.
	cmd := exec.Command("openssl", "pkcs12", "-export",
		"-inkey", keyPath,
		"-in", certPath,
		"-certfile", caPath,
		"-out", p12Path,
		"-passout", "pass:"+password,
		"-legacy",
	)
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("openssl pkcs12 -export failed: %w", err)
	}

	return &Result{
		Path:     p12Path,
		Password: password,
	}, cleanup, nil
}
