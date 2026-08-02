package cmd

import (
    "context"
    "fmt"
    "os"
    "github.com/adedayo/dnsaudit/pkg/scanner"
    "github.com/spf13/cobra"
)

// mtastsCmd represents the mtasts command
var mtastsCmd = &cobra.Command{
    Use:   "mtasts",
    Short: "Obtain the MTA‑STS TXT record for a domain.",
    Long:  `Lookup the _mta-sts TXT record for a domain to determine if MTA‑STS is published.`,
    Run: func(cmd *cobra.Command, args []string) {
        if len(args) == 1 {
            ctx := context.Background()
            if rec, err := scanner.CheckMTASts(ctx, args[0]); err == nil {
                fmt.Printf("%s\n", rec)
            } else {
                fmt.Fprintln(os.Stderr, err)
            }
        } else {
            cmd.Usage()
        }
    },
}

func init() {
    rootCmd.AddCommand(mtastsCmd)
}
