package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/adedayo/vantage/pkg/finding"
)

// Exit codes are a public contract. They are deliberately granular so that a
// caller — a CI pipeline, or an autonomous agent — can distinguish "the tool
// broke" from "the domain is misconfigured" without parsing any output. That
// distinction matters: conflating them means a resolver outage looks identical
// to a critical security finding.
const (
	// ExitOK means the run completed and nothing met the failure threshold.
	ExitOK = 0
	// ExitError means the tool itself could not do its job.
	ExitError = 1
	// ExitUsage means the invocation was malformed.
	ExitUsage = 2
	// ExitFindings means the run completed and at least one finding met or
	// exceeded --fail-on.
	ExitFindings = 3
	// ExitPartial means the run completed but one or more checks failed, so the
	// result is incomplete.
	ExitPartial = 4
)

// exitCodeError carries an explicit exit code up to Execute.
type exitCodeError struct {
	code int
	err  error
}

func (e *exitCodeError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}

func (e *exitCodeError) Unwrap() error { return e.err }

// withExitCode tags an error with the exit code the process should use.
func withExitCode(code int, err error) error {
	return &exitCodeError{code: code, err: err}
}

// exitCodeOf extracts the exit code an error implies, defaulting to ExitError.
func exitCodeOf(err error) int {
	if err == nil {
		return ExitOK
	}
	var coded *exitCodeError
	if errors.As(err, &coded) {
		return coded.code
	}
	return ExitError
}

// silentExit signals that the process should exit with a specific code without
// printing anything further, because output has already been rendered. It is
// used for the findings threshold: the findings themselves are the message.
type silentExit struct{ code int }

func (s *silentExit) Error() string { return "" }

// resultExitCode derives the process exit code from an assessment result and
// the configured failure threshold.
//
// The order matters. A findings threshold breach outranks a partial result,
// because a caller that asked to fail on high-severity findings needs to hear
// about them even if an unrelated check also failed.
func resultExitCode(result *finding.Result, failOn finding.Severity, failOnSet bool) int {
	if failOnSet {
		if max, ok := result.MaxSeverity(); ok && max >= failOn {
			return ExitFindings
		}
	}
	if result.HasFailures() {
		return ExitPartial
	}
	return ExitOK
}

// exit terminates the process, reporting err to stderr unless it is silent.
func exit(err error) {
	if err == nil {
		return
	}
	var silent *silentExit
	if errors.As(err, &silent) {
		os.Exit(silent.code)
	}
	if msg := err.Error(); msg != "" {
		fmt.Fprintln(os.Stderr, msg)
	}
	os.Exit(exitCodeOf(err))
}
