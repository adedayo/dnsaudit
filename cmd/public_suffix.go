package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/scanner"
)

// publicSuffixCmd validates whether a domain label is a public suffix.
var publicSuffixCmd = &cobra.Command{
	Use:   "public-suffix [domain]",
	Short: "Check whether a domain resolves to a registered public suffix.",
	Long: `Determine the effective top-level domain (eTLD / public suffix) for a given
domain name using the Mozilla Public Suffix List. This helps identify domains
that are registered directly at the public suffix boundary, which may indicate
infrastructure used for hosting, CDN edges, or subdomain-takeover risk.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		isPS, err := scanner.ValidatePublicSuffix(ctx, args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return err
		}
		if isPS {
			fmt.Printf("%s is a public suffix\n", args[0])
		} else {
			fmt.Printf("%s is NOT a public suffix\n", args[0])
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(publicSuffixCmd)
}
