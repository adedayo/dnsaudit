package audit

import "github.com/adedayo/dnsaudit/pkg/finding"

// GradeVersion identifies the grading algorithm.
//
// The version is emitted alongside the grade because a score that silently
// changes meaning between releases is worse than no score at all: trend lines
// become meaningless and an improvement can look like a regression. Any change
// to the thresholds below must bump this.
//
// Version 2 weighs confidence as well as severity. Version 1 counted a
// medium-confidence heuristic exactly as heavily as a deterministic protocol
// failure.
const GradeVersion = "2"

// Grade reduces a set of findings to a single letter, A to F.
//
// The algorithm is deliberately simple and severity-driven rather than a
// weighted score, because a defensible, explainable grade is more useful to a
// CISO than a precise-looking number nobody can reconstruct. Critical and high
// findings dominate: no quantity of low-severity hygiene issues can drag a
// domain below C, and a single critical cannot be offset by anything.
//
// Severity is adjusted by confidence first. The catalogue records how strongly
// the evidence supports each rule, and grading on severity alone threw that
// away at the one point where it mattered most: a keyword guess about a
// hostname counted as heavily as an unsigned delegation the resolver proved.
// A guess should be reported, but it should not decide the grade on its own.
//
// Findings keep their catalogue severity everywhere else. Only the grade is
// adjusted, so the counts a reader sees still describe what was found.
func Grade(findings []finding.Finding) string {
	var critical, high, medium, low int
	for _, f := range findings {
		// Suppressed findings are risks the operator has accepted, and an
		// accepted risk must not keep driving the grade down.
		if f.Suppressed {
			continue
		}
		switch gradingSeverity(f) {
		case finding.SeverityCritical:
			critical++
		case finding.SeverityHigh:
			high++
		case finding.SeverityMedium:
			medium++
		case finding.SeverityLow:
			low++
		case finding.SeverityInfo:
			// Informational findings describe the estate rather than a
			// weakness in it, and never affect the grade.
		}
	}

	switch {
	case critical > 0:
		return "F"
	case high >= 3:
		return "E"
	case high > 0:
		return "D"
	case medium >= 3:
		return "C"
	case medium > 0:
		return "B"
	case low > 0:
		return "B"
	default:
		return "A"
	}
}

// gradingSeverity lowers a finding's severity to reflect how firmly it is
// established: one band for medium confidence, two for low.
//
// Demotion rather than exclusion, because a medium-confidence high-severity
// finding is still worth something to the grade — it is a real possibility, not
// a certainty, and the grade should say so. Nothing falls below info, so a
// low-confidence critical still lands at medium and remains visible.
func gradingSeverity(f finding.Finding) finding.Severity {
	demotion := 0
	switch f.Confidence {
	case finding.ConfidenceMedium:
		demotion = 1
	case finding.ConfidenceLow:
		demotion = 2
	case finding.ConfidenceHigh:
		demotion = 0
	}

	severity := f.Severity
	for ; demotion > 0 && severity > finding.SeverityInfo; demotion-- {
		severity--
	}
	return severity
}

// GradeDescription explains what a grade means, for report footers and the
// forthcoming capability manifest.
func GradeDescription(grade string) string {
	switch grade {
	case "A":
		return "No issues identified by the checks that ran."
	case "B":
		return "Minor issues only; no enforcement gaps."
	case "C":
		return "Several moderate issues; review recommended."
	case "D":
		return "A high-severity issue is present and should be addressed."
	case "E":
		return "Multiple high-severity issues; prioritise remediation."
	case "F":
		return "A critical issue is present and needs immediate attention."
	default:
		return "Ungraded."
	}
}
