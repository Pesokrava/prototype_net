// Package contract parses contract.toml to extract the synthetic prefix CIDR.
package contract

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Contract represents the relevant fields from contract.toml.
type Contract struct {
	Address struct {
		SyntheticPrefixCIDR string `toml:"synthetic_prefix_cidr"`
	} `toml:"address"`
}

// Load reads contract.toml from path and returns the parsed contract.
func Load(path string) (*Contract, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading contract file: %w", err)
	}

	var c Contract
	if err := toml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing contract TOML: %w", err)
	}

	if c.Address.SyntheticPrefixCIDR == "" {
		return nil, fmt.Errorf("contract.toml missing address.synthetic_prefix_cidr")
	}

	return &c, nil
}

// SyntheticPrefix returns the synthetic prefix CIDR string (e.g. "fd00:abcd::/32").
func (c *Contract) SyntheticPrefix() string {
	return c.Address.SyntheticPrefixCIDR
}
