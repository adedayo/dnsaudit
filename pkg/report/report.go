// Package report renders assessment results in the formats consumers need:
// readable text for analysts, JSON and NDJSON for automation and agents, CSV
// for spreadsheets, and SARIF for code-scanning platforms.
//
// Renderers never write to stderr and never emit partial fragments, so that
// `vantage ... -o json > out.json` always yields a parseable document.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/adedayo/vantage/pkg/finding"
)

// Format identifies an output renderer.
type Format string

// Supported output formats.
const (
	FormatText   Format = "text"
	FormatJSON   Format = "json"
	FormatNDJSON Format = "ndjson"
	FormatCSV    Format = "csv"
	FormatSARIF  Format = "sarif"
)

// Formats returns the supported formats in a stable order, for help text and
// the capability manifest.
func Formats() []string {
	return []string{
		string(FormatText), string(FormatJSON), string(FormatNDJSON),
		string(FormatCSV), string(FormatSARIF),
	}
}

// ParseFormat validates a format name.
func ParseFormat(s string) (Format, error) {
	f := Format(strings.ToLower(strings.TrimSpace(s)))
	switch f {
	case FormatText, FormatJSON, FormatNDJSON, FormatCSV, FormatSARIF:
		return f, nil
	}
	return "", fmt.Errorf("error: unknown format %q (want one of: %s)", s, strings.Join(Formats(), ", "))
}

// Structured reports whether the format is machine-readable, which callers use
// to decide whether to suppress human-oriented chatter.
func (f Format) Structured() bool { return f != FormatText }

// Options controls rendering.
type Options struct {
	// Format selects the renderer.
	Format Format
	// MinSeverity filters out findings below the given level.
	MinSeverity finding.Severity
	// Fields projects a subset of finding fields. Empty means all fields.
	Fields []string
	// Summary omits per-finding detail, emitting counts only.
	Summary bool
	// NoCatalogueText omits description and remediation prose. Consumers can
	// resolve the text later from the catalogue by ID, which keeps repeated
	// automated runs cheap without losing access to the guidance.
	NoCatalogueText bool
	// Colour enables ANSI colour in text output.
	Colour bool
	// Quiet suppresses non-essential text output.
	Quiet bool
}

// DefaultOptions returns options suitable for interactive use.
func DefaultOptions() Options {
	return Options{Format: FormatText, MinSeverity: finding.SeverityInfo}
}

// Render writes the result to w in the configured format.
func Render(w io.Writer, result *finding.Result, opts Options) error {
	result.Finalise()

	if opts.MinSeverity > finding.SeverityInfo {
		result = result.Filter(opts.MinSeverity)
	}
	if opts.NoCatalogueText || len(opts.Fields) > 0 {
		result = project(result, opts)
	}

	switch opts.Format {
	case FormatText:
		return renderText(w, result, opts)
	case FormatJSON:
		return renderJSON(w, result, opts)
	case FormatNDJSON:
		return renderNDJSON(w, result, opts)
	case FormatCSV:
		return renderCSV(w, result, opts)
	case FormatSARIF:
		return renderSARIF(w, result)
	}
	return fmt.Errorf("error: unknown format %q", opts.Format)
}

// project applies the token-economy options, returning a copy so the caller's
// result is never mutated.
func project(result *finding.Result, opts Options) *finding.Result {
	clone := *result
	findings := make([]finding.Finding, 0, len(result.Findings))

	keep := map[string]bool{}
	for _, f := range opts.Fields {
		keep[strings.ToLower(strings.TrimSpace(f))] = true
	}
	all := len(keep) == 0

	for _, f := range result.Findings {
		if opts.NoCatalogueText {
			f.Description = ""
			f.Remediation = ""
			f.References = nil
		}
		if !all {
			f = projectFields(f, keep)
		}
		findings = append(findings, f)
	}
	clone.Findings = findings
	return &clone
}

// projectFields blanks every field not named in keep. ID and Target are always
// retained: a finding without them is not interpretable, so allowing them to be
// projected away would produce output that looks valid but says nothing.
func projectFields(f finding.Finding, keep map[string]bool) finding.Finding {
	out := finding.Finding{ID: f.ID, Target: f.Target}
	if keep["title"] {
		out.Title = f.Title
	}
	if keep["severity"] {
		out.Severity = f.Severity
	}
	if keep["confidence"] {
		out.Confidence = f.Confidence
	}
	if keep["check"] {
		out.Check = f.Check
	}
	if keep["description"] {
		out.Description = f.Description
	}
	if keep["evidence"] {
		out.Evidence = f.Evidence
	}
	if keep["remediation"] {
		out.Remediation = f.Remediation
	}
	if keep["references"] {
		out.References = f.References
	}
	if keep["tags"] {
		out.Tags = f.Tags
	}
	out.Suppressed = f.Suppressed
	return out
}

// FieldNames lists the projectable field names, for help text and the manifest.
func FieldNames() []string {
	names := []string{
		"title", "severity", "confidence", "check", "description",
		"evidence", "remediation", "references", "tags",
	}
	sort.Strings(names)
	return names
}
