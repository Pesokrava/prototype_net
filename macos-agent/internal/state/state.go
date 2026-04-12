// Package state manages persistent local state in ~/.prototype-net/.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	stateDir       = ".prototype-net"
	configFileName = "config.json"
	dnsBackupFile  = "dns-backup.json"
)

// Config holds non-secret operational metadata persisted after setup.
type Config struct {
	ServerIP        string `json:"server_ip"`
	DNSIP           string `json:"dns_ip"`
	ClientID        string `json:"client_id"`
	SyntheticPrefix string `json:"synthetic_prefix"`
	ProfileName     string `json:"profile_name"`
	CAIssuerCN      string `json:"ca_issuer_cn"`
}

// DNSBackup holds the DNS state before the agent modified it.
type DNSBackup struct {
	Service string   `json:"service"`
	Servers []string `json:"servers"`
}

// Dir returns the absolute path to ~/.prototype-net/.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home directory: %w", err)
	}
	return filepath.Join(home, stateDir), nil
}

// ensureDir creates the state directory if it doesn't exist.
func ensureDir() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating state directory %s: %w", dir, err)
	}
	return dir, nil
}

// SaveConfig persists the setup configuration.
func SaveConfig(cfg *Config) error {
	dir, err := ensureDir()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling config: %w", err)
	}

	path := filepath.Join(dir, configFileName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	return nil
}

// LoadConfig reads the saved configuration.
func LoadConfig() (*Config, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, configFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config (did you run 'setup' first?): %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return &cfg, nil
}

// ConfigExists checks whether the config file exists.
func ConfigExists() bool {
	dir, err := Dir()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, configFileName))
	return err == nil
}

// SaveDNSBackup persists the DNS backup state.
func SaveDNSBackup(backup *DNSBackup) error {
	dir, err := ensureDir()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling DNS backup: %w", err)
	}

	path := filepath.Join(dir, dnsBackupFile)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing DNS backup: %w", err)
	}

	return nil
}

// LoadDNSBackup reads the saved DNS backup.
func LoadDNSBackup() (*DNSBackup, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, dnsBackupFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading DNS backup: %w", err)
	}

	var backup DNSBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return nil, fmt.Errorf("parsing DNS backup: %w", err)
	}

	return &backup, nil
}

// DNSBackupExists checks whether the DNS backup file exists.
func DNSBackupExists() bool {
	dir, err := Dir()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, dnsBackupFile))
	return err == nil
}

// RemoveDNSBackup deletes the DNS backup file.
func RemoveDNSBackup() error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, dnsBackupFile)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing DNS backup: %w", err)
	}
	return nil
}
