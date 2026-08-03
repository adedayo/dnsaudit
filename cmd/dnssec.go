package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/adedayo/dnsaudit/pkg/scanner"
)

// dnssecCmd checks whether DNSSEC is enabled for a domain.
var dnssecCmd = &cobra.Command{
	Use:   "dnssec [domain]",
	Short: "Check whether DNSSEC (DNSKEY) is enabled for a domain.",
	Long: `Query the DNSKEY records of a domain to determine whether DNSSEC is enabled.
DNSSEC provides cryptographic authentication of DNS data, protecting against
cache poisoning and DNS spoofing attacks.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		status, err := scanner.CheckDNSSEC(ctx, args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return err
		}
		fmt.Printf("DNSSEC: %s for %s\n", status, args[0])
		return nil
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.AddCommand(dnssecCmd)
}
