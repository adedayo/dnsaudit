package audit

import "github.com/adedayo/dnsaudit/pkg/finding"

// GradeVersion identifies the grading algorithm.
//
// The version is emitted alongside the grade because a score that silently
// changes meaning between releases is worse than no score at all: trend lines
// become meaningless and an improvement can look like a regression. Any change
// to the thresholds below must bump this.
const GradeVersion = "1"

// Grade reduces a summary to a single letter, A to F.
//
// The algorithm is deliberately simple and severity-driven rather than a
// weighted score, because a defensible, explainable grade is more useful to a
// CISO than a precise-looking number nobody can reconstruct. Critical and high
// findings dominate: no quantity of low-severity hygiene issues can drag a
// domain below C, and a single critical cannot be offset by anything.
func Grade(s finding.Summary) string {
	switch {
	case s.Critical > 0:
		return "F"
	case s.High >= 3:
		return "E"
	case s.High > 0:
		return "D"
	case s.Medium >= 3:
		return "C"
	case s.Medium > 0:
		return "B"
	case s.Low > 0:
		return "B"
	default:
		return "A"
	}
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
