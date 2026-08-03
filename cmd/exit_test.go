package cmd

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/adedayo/dnsaudit/pkg/finding"
)

// TestResultExitCode pins down the contract automated consumers depend on.
// The distinction between "the tool broke" (1) and "the domain is
// misconfigured" (3) is the whole point: conflating them means a resolver
// outage is indistinguishable from a critical security finding.
func TestResultExitCode(t *testing.T) {
	withFindings := func(severities ...finding.Severity) *finding.Result {
		r := finding.NewResult("dnsaudit", "test")
		ids := map[finding.Severity]string{
			finding.SeverityCritical: "DNSA-SPF-004",
			finding.SeverityHigh:     "DNSA-DMARC-001",
			finding.SeverityMedium:   "DNSA-DMARC-005",
			finding.SeverityLow:      "DNSA-SPF-005",
		}
		for _, s := range severities {
			r.Add(finding.New(ids[s], "example.com"))
		}
		r.Finalise()
		return r
	}

	tests := map[string]struct {
		result     *finding.Result
		failOn     finding.Severity
		failOnSet  bool
		wantStatus int
	}{
		"clean run": {
			result:     withFindings(),
			wantStatus: ExitOK,
		},
		"findings but no threshold set": {
			result:     withFindings(finding.SeverityCritical),
			wantStatus: ExitOK,
		},
		"finding meets the threshold": {
			result:     withFindings(finding.SeverityHigh),
			failOn:     finding.SeverityHigh,
			failOnSet:  true,
			wantStatus: ExitFindings,
		},
		"finding exceeds the threshold": {
			result:     withFindings(finding.SeverityCritical),
			failOn:     finding.SeverityHigh,
			failOnSet:  true,
			wantStatus: ExitFindings,
		},
		"finding below the threshold": {
			result:     withFindings(finding.SeverityLow),
			failOn:     finding.SeverityHigh,
			failOnSet:  true,
			wantStatus: ExitOK,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := resultExitCode(tc.result, tc.failOn, tc.failOnSet)
			assert.Equal(t, tc.wantStatus, got)
		})
	}
}

func TestResultExitCodePartial(t *testing.T) {
	r := finding.NewResult("dnsaudit", "test")
	r.AddError(finding.CheckError{Check: "spf", Code: finding.ErrCodeTimeout, Message: "timed out"})
	r.Finalise()

	assert.Equal(t, ExitPartial, resultExitCode(r, finding.SeverityInfo, false))
}

// TestFindingsOutrankPartialResults: a caller that asked to fail on high
// severity findings needs to hear about them even when an unrelated check also
// failed, so the threshold breach must win.
func TestFindingsOutrankPartialResults(t *testing.T) {
	r := finding.NewResult("dnsaudit", "test")
	r.Add(finding.New("DNSA-SPF-004", "example.com"))
	r.AddError(finding.CheckError{Check: "dkim", Code: finding.ErrCodeTimeout, Message: "timed out"})
	r.Finalise()

	assert.Equal(t, ExitFindings, resultExitCode(r, finding.SeverityHigh, true))
}

func TestSuppressedFindingsDoNotTriggerFailure(t *testing.T) {
	suppressed := finding.New("DNSA-SPF-004", "example.com")
	suppressed.Suppressed = true

	r := finding.NewResult("dnsaudit", "test")
	r.Add(suppressed)
	r.Finalise()

	assert.Equal(t, ExitOK, resultExitCode(r, finding.SeverityHigh, true),
		"an accepted risk must not fail the build")
}

func TestExitCodeOf(t *testing.T) {
	assert.Equal(t, ExitOK, exitCodeOf(nil))
	assert.Equal(t, ExitError, exitCodeOf(errors.New("boom")))
	assert.Equal(t, ExitUsage, exitCodeOf(withExitCode(ExitUsage, errors.New("bad flag"))))
}

func TestExitCodeErrorUnwraps(t *testing.T) {
	inner := errors.New("root cause")
	wrapped := withExitCode(ExitUsage, inner)

	assert.ErrorIs(t, wrapped, inner)
	assert.Equal(t, "root cause", wrapped.Error())
}

func TestCheckErrorClassification(t *testing.T) {
	tests := map[string]struct {
		err           error
		wantCode      finding.ErrorCode
		wantRetryable bool
	}{
		"timeout is retryable": {
			err:           errors.New("error: dns query failed: i/o timeout"),
			wantCode:      finding.ErrCodeTimeout,
			wantRetryable: true,
		},
		"resolver failure is retryable": {
			err:           errors.New("error: dns query failed: connection refused"),
			wantCode:      finding.ErrCodeResolverUnreachable,
			wantRetryable: true,
		},
		"not found is not retryable": {
			err:      errors.New("error: not found"),
			wantCode: finding.ErrCodeNotFound,
		},
		"malformed record": {
			err:      errors.New("error: malformed response"),
			wantCode: finding.ErrCodeInvalidRecord,
		},
		"unrecognised errors are internal": {
			err:      errors.New("something unexpected"),
			wantCode: finding.ErrCodeInternal,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := checkError("spf", "example.com", tc.err)
			assert.Equal(t, tc.wantCode, got.Code)
			assert.Equal(t, tc.wantRetryable, got.Retryable)
			if tc.wantRetryable {
				assert.Positive(t, got.RetryAfterSeconds,
					"a retryable error should tell the caller how long to wait")
			}
		})
	}
}

func TestIsNotFound(t *testing.T) {
	assert.True(t, isNotFound(errors.New("error: not found")))
	assert.False(t, isNotFound(errors.New("error: dns query failed")))
}
