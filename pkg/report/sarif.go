package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/adedayo/dnsaudit/pkg/finding"
)

// SARIF 2.1.0 output, for GitHub code scanning, DefectDojo and similar.
//
// Only the subset of the schema dnsaudit can populate honestly is emitted. DNS
// findings have no source file or line, so each result is located by a logical
// location (the target domain) rather than a fabricated physical one.

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name,omitempty"`
	ShortDescription     sarifText              `json:"shortDescription"`
	FullDescription      sarifText              `json:"fullDescription,omitempty"`
	Help                 sarifText              `json:"help,omitempty"`
	HelpURI              string                 `json:"helpUri,omitempty"`
	Properties           map[string]any         `json:"properties,omitempty"`
	DefaultConfiguration sarifRuleConfiguration `json:"defaultConfiguration"`
}

type sarifRuleConfiguration struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
	// PartialFingerprints let consumers track a finding across runs even as
	// surrounding output changes.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
	Suppressions        []sarifSuppress   `json:"suppressions,omitempty"`
}

type sarifSuppress struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// sarifLevel maps dnsaudit severities onto the four SARIF levels. SARIF has no
// "critical", so critical and high both map to "error"; the original severity
// is preserved in properties so nothing is lost.
func sarifLevel(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	case finding.SeverityLow:
		return "note"
	default:
		return "note"
	}
}

func renderSARIF(w io.Writer, result *finding.Result) error {
	rules := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(result.Findings))

	for _, f := range result.Findings {
		if _, seen := rules[f.ID]; !seen {
			rule := sarifRule{
				ID:                   f.ID,
				Name:                 f.Check,
				ShortDescription:     sarifText{Text: f.Title},
				DefaultConfiguration: sarifRuleConfiguration{Level: sarifLevel(f.Severity)},
				Properties: map[string]any{
					"severity": f.Severity.String(),
					"tags":     f.Tags,
				},
			}
			if entry, ok := finding.Lookup(f.ID); ok {
				rule.FullDescription = sarifText{Text: entry.Description}
				rule.Help = sarifText{Text: entry.Remediation}
				if len(entry.References) > 0 {
					rule.HelpURI = entry.References[0]
				}
			}
			rules[f.ID] = rule
		}

		res := sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: sarifMessage(f)},
			Locations: []sarifLocation{{
				LogicalLocations: []sarifLogicalLocation{{Name: f.Target, Kind: "resource"}},
			}},
			PartialFingerprints: map[string]string{
				"dnsauditFinding/v1": f.ID + ":" + f.Target,
			},
			Properties: map[string]any{
				"confidence": f.Confidence.String(),
				"check":      f.Check,
			},
		}
		if f.Suppressed {
			res.Suppressions = []sarifSuppress{{
				Kind: "external", Justification: f.SuppressionReason,
			}}
		}
		results = append(results, res)
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           result.Tool.Name,
				Version:        result.Tool.Version,
				InformationURI: "https://github.com/adedayo/dnsaudit",
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

// sarifMessage combines the title with the evidence, because SARIF consumers
// typically surface only the message and the reader needs the evidence to act.
func sarifMessage(f finding.Finding) string {
	msg := f.Title
	if len(f.Evidence) > 0 {
		msg += " (" + evidenceLine(f.Evidence[0]) + ")"
	}
	if f.Target != "" {
		msg = fmt.Sprintf("%s: %s", f.Target, msg)
	}
	return msg
}
