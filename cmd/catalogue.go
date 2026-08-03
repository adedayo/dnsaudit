package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/finding"
)

// catalogueCmd exposes the finding catalogue.
//
// Publishing the catalogue matters for two reasons. It lets a reader look up
// what a finding ID means without running an assessment, and it lets an
// automated consumer resolve remediation guidance from a reviewed,
// version-controlled source rather than composing advice itself.
var catalogueCmd = &cobra.Command{
	Use:   "catalogue",
	Short: "List every finding vantage can report.",
	Long: `Print the finding catalogue: every identifier the tool can raise, with its
default severity, description, remediation guidance and references.

Identifiers are stable and permanent. Once published, an ID is never reassigned
or given a different meaning, so it is safe to key tickets and suppressions on
them.`,
	Aliases: []string{"catalog"},
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		entries := finding.Catalogue()
		if checkFilter != "" {
			entries = finding.CatalogueForCheck(checkFilter)
			if len(entries) == 0 {
				return withExitCode(ExitUsage, fmt.Errorf(
					"error: no findings for check %q (known checks: %s)",
					checkFilter, strings.Join(finding.Checks(), ", ")))
			}
		}

		if structuredOutput() {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)
			return enc.Encode(exportEntries(entries))
		}

		for _, e := range entries {
			fmt.Printf("%-18s %-9s %s\n", e.ID, strings.ToUpper(e.Severity.String()), e.Title)
		}
		return nil
	},
}

// explainCmd expands a single catalogue entry.
var explainCmd = &cobra.Command{
	Use:   "explain [finding-id]",
	Short: "Explain a finding and how to remediate it.",
	Long: `Print the full catalogue entry for a finding identifier, including why the
condition matters, how to fix it, and the standard that governs it.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := strings.ToUpper(strings.TrimSpace(args[0]))
		entry, ok := finding.Lookup(id)
		if !ok {
			return withExitCode(ExitUsage, fmt.Errorf(
				"error: unknown finding %q (list them with 'vantage catalogue')", args[0]))
		}

		if structuredOutput() {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)
			return enc.Encode(exportEntry(entry))
		}

		fmt.Printf("%s  [%s]\n\n", entry.ID, strings.ToUpper(entry.Severity.String()))
		fmt.Printf("%s\n\n", entry.Title)
		fmt.Printf("Check       : %s\n", entry.Check)
		fmt.Printf("Severity    : %s\n", entry.Severity)
		fmt.Printf("Confidence  : %s\n\n", entry.Confidence)
		fmt.Printf("What it means\n  %s\n\n", indentWrap(entry.Description))
		fmt.Printf("How to fix it\n  %s\n\n", indentWrap(entry.Remediation))
		if len(entry.References) > 0 {
			fmt.Println("References")
			for _, r := range entry.References {
				fmt.Printf("  %s\n", r)
			}
		}
		if len(entry.Tags) > 0 {
			fmt.Printf("\nTags        : %s\n", strings.Join(entry.Tags, ", "))
		}
		return nil
	},
}

// exportedEntry is the JSON shape of a catalogue entry. It is defined
// explicitly rather than tagging finding.Entry, so that the public schema is
// visible in one place and cannot drift accidentally.
type exportedEntry struct {
	ID          string   `json:"id"`
	Check       string   `json:"check"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

func exportEntry(e finding.Entry) exportedEntry {
	return exportedEntry{
		ID: e.ID, Check: e.Check, Title: e.Title,
		Severity: e.Severity.String(), Confidence: e.Confidence.String(),
		Description: e.Description, Remediation: e.Remediation,
		References: e.References, Tags: e.Tags,
	}
}

func exportEntries(entries []finding.Entry) []exportedEntry {
	out := make([]exportedEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, exportEntry(e))
	}
	return out
}

// indentWrap wraps prose to a readable width for terminal output.
func indentWrap(text string) string {
	const width = 76
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	lines := []string{words[0]}
	for _, word := range words[1:] {
		last := len(lines) - 1
		if len(lines[last])+1+len(word) > width {
			lines = append(lines, word)
			continue
		}
		lines[last] += " " + word
	}
	return strings.Join(lines, "\n  ")
}

// checkFilter holds the --check flag for the catalogue command.
var checkFilter string

func init() {
	catalogueCmd.Flags().StringVar(&checkFilter, "check", "",
		"Only list findings belonging to this check, e.g. --check spf.")
	rootCmd.AddCommand(catalogueCmd)
	rootCmd.AddCommand(explainCmd)
}
