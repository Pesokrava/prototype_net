package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"prototype-net/macos-agent/internal/bundle"
	"prototype-net/macos-agent/internal/contract"
	"prototype-net/macos-agent/internal/mobileconfig"
	"prototype-net/macos-agent/internal/pkcs12"
	"prototype-net/macos-agent/internal/state"

	"github.com/spf13/cobra"
)

var (
	flagServerIP     string
	flagDNSIP        string
	flagBundleFile   string
	flagContractFile string
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Import client bundle and install VPN profile",
	Long: `Parse a client bundle JSON file, generate a .mobileconfig profile,
and open it for installation in macOS System Settings.`,
	RunE: runSetup,
}

func init() {
	setupCmd.Flags().StringVar(&flagServerIP, "server-ip", "", "VPN server IP address (required)")
	setupCmd.Flags().StringVar(&flagDNSIP, "dns-ip", "", "DNS server IP address (required)")
	setupCmd.Flags().StringVar(&flagBundleFile, "bundle-file", "", "Path to client bundle JSON (required)")
	setupCmd.Flags().StringVar(&flagContractFile, "contract-file", "./contract.toml", "Path to contract.toml")

	_ = setupCmd.MarkFlagRequired("server-ip")
	_ = setupCmd.MarkFlagRequired("dns-ip")
	_ = setupCmd.MarkFlagRequired("bundle-file")
}

func runSetup(cmd *cobra.Command, args []string) error {
	// Step 1: Parse and validate bundle.
	fmt.Println("==> Loading client bundle...")
	b, err := bundle.Load(flagBundleFile)
	if err != nil {
		return fmt.Errorf("loading bundle: %w", err)
	}
	fmt.Printf("    Client ID: %s\n", b.ClientID)

	// Step 2: Parse contract.toml for synthetic prefix.
	fmt.Printf("==> Reading contract from %s...\n", flagContractFile)
	c, err := contract.Load(flagContractFile)
	if err != nil {
		return fmt.Errorf("loading contract: %w", err)
	}
	syntheticPrefix := c.SyntheticPrefix()
	fmt.Printf("    Synthetic prefix: %s\n", syntheticPrefix)

	// Step 3: Extract CA issuer CN.
	caIssuerCN, err := b.CAIssuerCN()
	if err != nil {
		return fmt.Errorf("extracting CA issuer CN: %w", err)
	}
	fmt.Printf("    CA issuer CN: %s\n", caIssuerCN)

	// Step 4: Parse CA cert DER for the mobileconfig payload.
	caCert, err := b.ParseCACert()
	if err != nil {
		return fmt.Errorf("parsing CA cert: %w", err)
	}

	// Step 5: Get PKCS#12 data — prefer pre-generated from bundle, fall back
	// to runtime generation if not present.
	var p12Data []byte
	var p12Password string

	if b.HasPKCS12() {
		fmt.Println("==> Using pre-generated PKCS#12 from bundle...")
		p12Data, err = b.DecodePKCS12()
		if err != nil {
			return fmt.Errorf("decoding pre-generated PKCS#12: %w", err)
		}
		p12Password = b.PKCS12Password
	} else {
		fmt.Println("==> Bundle has no pre-generated PKCS#12, generating at runtime...")
		fmt.Println("    WARNING: Runtime P12 generation requires OpenSSL 3.x.")
		fmt.Println("    LibreSSL (macOS default) produces incompatible P12 files.")
		fmt.Println("    Re-generate the bundle with gen-client.sh for best results.")
		p12Result, cleanup, genErr := pkcs12.Generate(b.ClientCertPEM, b.ClientKeyPEM, b.CACertPEM)
		if genErr != nil {
			return fmt.Errorf("generating PKCS#12: %w", genErr)
		}
		defer cleanup()

		p12Data, err = os.ReadFile(p12Result.Path)
		if err != nil {
			return fmt.Errorf("reading PKCS#12 file: %w", err)
		}
		p12Password = p12Result.Password
	}

	// Step 6: Determine profile output path.
	stateDir, err := state.Dir()
	if err != nil {
		return fmt.Errorf("getting state directory: %w", err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}

	profileName := "prototype-net"
	profilePath := filepath.Join(stateDir, profileName+".mobileconfig")

	// Step 7: Generate .mobileconfig.
	fmt.Printf("==> Generating .mobileconfig at %s...\n", profilePath)

	err = mobileconfig.Generate(profilePath, &mobileconfig.Params{
		ServerIP:       flagServerIP,
		ClientID:       b.ClientID,
		CAIssuerCN:     caIssuerCN,
		CACertDER:      caCert.Raw,
		PKCS12Data:     p12Data,
		PKCS12Password: p12Password,
		ProfileName:    profileName,
	})
	if err != nil {
		return fmt.Errorf("generating mobileconfig: %w", err)
	}

	// Step 8: Open the profile for user installation.
	fmt.Println("==> Opening profile for installation...")
	if err := exec.Command("open", profilePath).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not open profile automatically: %v\n", err)
		fmt.Fprintf(os.Stderr, "         Please open %s manually in System Settings > Profiles\n", profilePath)
	} else {
		fmt.Println("    Profile opened. Install it in System Settings > Profiles.")
	}

	// Step 9: Persist config.
	fmt.Println("==> Saving configuration...")
	cfg := &state.Config{
		ServerIP:        flagServerIP,
		DNSIP:           flagDNSIP,
		ClientID:        b.ClientID,
		SyntheticPrefix: syntheticPrefix,
		ProfileName:     profileName,
		CAIssuerCN:      caIssuerCN,
	}
	if err := state.SaveConfig(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	fmt.Println("==> Setup complete.")
	fmt.Println("    After installing the profile, run: macos-agent start")

	return nil
}
