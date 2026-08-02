package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/adedayo/dnsaudit/pkg/scanner"
	"github.com/spf13/cobra"
)

// caaCmd retrieves Certification Authority Authorization records.
var caaCmd = &cobra.Command{
	Use:   "caa [domain]",
	Short: "Retrieve CAA records for a domain.",
	Long: `Query DNS Certification Authority Authorization (CAA) records for a domain.
CAA records restrict which certificate authorities (CAs) are permitted to issue
TLS certificates for the domain, reducing the risk of mis-issuance.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		records, err := scanner.LookupCAA(ctx, args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return err
		}
		for _, r := range records {
			fmt.Println(r)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(caaCmd)
}
