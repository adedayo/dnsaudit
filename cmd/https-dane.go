package cmd

import (
    "context"
    "fmt"
    "os"
    "github.com/spf13/cobra"
    "github.com/adedayo/dnsaudit/pkg/scanner"
)

// httpsDaneCmd represents the https-dane command
var httpsDaneCmd = &cobra.Command{
    Use:   "https-dane [domain]",
    Short: "Retrieve TLSA records for HTTPS service (_443._tcp)",
    Args:  cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        domain := args[0]
        ctx := context.Background()
        result, err := scanner.LookupTLSAHTTPS(ctx, domain)
        if err != nil {
            return fmt.Errorf("lookup failed: %w", err)
        }
        fmt.Fprintln(os.Stdout, result)
        return nil
    },
}

func init() {
    rootCmd.AddCommand(httpsDaneCmd)
}
