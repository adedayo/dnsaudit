package audit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	dnsaudit "github.com/adedayo/dnsaudit/pkg"
	"github.com/adedayo/dnsaudit/pkg/finding"
)

// Default concurrency limits. They are deliberately modest: the tool queries
// infrastructure that belongs to someone else, and an audit that looks like a
// flood is both rude and likely to be rate-limited into producing wrong
// answers.
const (
	DefaultConcurrency      = 8
	DefaultCheckConcurrency = 6
)

// Runner executes checks against targets.
type Runner struct {
	// Checks to run against every target.
	Checks []Check
	// Concurrency bounds how many targets are assessed at once.
	Concurrency int
	// CheckConcurrency bounds how many checks run at once per target.
	CheckConcurrency int
	// NoNetwork restricts checks to DNS only.
	NoNetwork bool
	// Progress, when non-nil, is called as each target completes. It is invoked
	// from multiple goroutines, so implementations must be safe for concurrent
	// use.
	Progress func(target string, done, total int)
}

// targetResult holds one target's outcome before merging.
type targetResult struct {
	index    int
	target   string
	findings []finding.Finding
	checks   []finding.CheckResult
	errs     []finding.CheckError
}

// Run assesses every target and merges the outcomes into a single result.
//
// A check that fails never aborts the run: its failure is recorded as a
// structured error and the remaining checks continue. A partial answer that
// says which parts are missing is far more useful than no answer at all.
func (r *Runner) Run(ctx context.Context, result *finding.Result, targets ...string) error {
	if len(r.Checks) == 0 {
		return errors.New("error: no checks selected")
	}
	targets = normaliseTargets(targets)
	if len(targets) == 0 {
		return errors.New("error: no targets supplied")
	}

	concurrency := r.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results = make([]targetResult, len(targets))
		done    int
		sem     = make(chan struct{}, concurrency)
	)

	for i, target := range targets {
		wg.Add(1)
		go func(i int, target string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			out := r.runTarget(ctx, i, target)

			mu.Lock()
			results[i] = out
			done++
			progress := r.Progress
			completed := done
			mu.Unlock()

			if progress != nil {
				progress(target, completed, len(targets))
			}
		}(i, target)
	}
	wg.Wait()

	// Merge in target order so that output does not depend on which goroutine
	// happened to finish first. Determinism is what makes the output diffable.
	for _, out := range results {
		if out.target == "" {
			continue
		}
		result.AddTarget(out.target)
		result.Add(out.findings...)
		result.Checks = append(result.Checks, out.checks...)
		for _, e := range out.errs {
			result.AddError(e)
		}
	}
	result.Resolvers = dnsaudit.Resolvers()
	result.Finalise()
	result.Summary.Grade = Grade(result.Summary)
	result.Summary.GradeVersion = GradeVersion

	return ctx.Err()
}

// runTarget assesses one target with all selected checks.
func (r *Runner) runTarget(ctx context.Context, index int, target string) targetResult {
	out := targetResult{index: index, target: target}

	checkConcurrency := r.CheckConcurrency
	if checkConcurrency <= 0 {
		checkConcurrency = DefaultCheckConcurrency
	}

	// One cache per target: records for different domains share nothing, and a
	// per-target cache keeps memory bounded when assessing a large portfolio.
	t := Target{Domain: target, Cache: NewCache(), NoNetwork: r.NoNetwork}

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		sem = make(chan struct{}, checkConcurrency)
	)

	for _, check := range r.Checks {
		wg.Add(1)
		go func(check Check) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			name := check.Describe().Name
			outcome, err := check.Run(ctx, t)

			mu.Lock()
			defer mu.Unlock()

			switch {
			case err != nil && errors.Is(err, dnsaudit.ErrNotFound):
				out.checks = append(out.checks, finding.CheckResult{
					Check: name, Target: target, State: finding.StateNotFound,
				})
				out.findings = append(out.findings, outcome.Findings...)
			case err != nil:
				out.checks = append(out.checks, finding.CheckResult{
					Check: name, Target: target, State: finding.StateCheckFailed,
				})
				out.errs = append(out.errs, ClassifyError(name, target, err))
			default:
				state := outcome.State
				if state == "" {
					state = finding.StateOK
				}
				out.checks = append(out.checks, finding.CheckResult{
					Check: name, Target: target, State: state, Records: outcome.Records,
				})
				out.findings = append(out.findings, outcome.Findings...)
			}
		}(check)
	}
	wg.Wait()

	return out
}

// normaliseTargets trims, lower-cases and de-duplicates targets while
// preserving the caller's ordering.
func normaliseTargets(targets []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		t = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(t), ".")))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// ClassifyError converts a check failure into a structured error with a stable
// code and a retry hint, so an automated consumer never has to interpret the
// wording of a message.
func ClassifyError(check, target string, err error) finding.CheckError {
	msg := err.Error()
	code := finding.ErrCodeInternal
	retryable := false

	switch {
	case errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		code, retryable = finding.ErrCodeTimeout, true
	case strings.Contains(msg, "dns query failed") ||
		strings.Contains(msg, "no DNS resolvers") ||
		strings.Contains(msg, "no resolvers"):
		code, retryable = finding.ErrCodeResolverUnreachable, true
	case errors.Is(err, dnsaudit.ErrNotFound) || strings.Contains(msg, "not found"):
		code = finding.ErrCodeNotFound
	case strings.Contains(msg, "network disabled"):
		code = finding.ErrCodeNetworkDisabled
	case strings.Contains(msg, "invalid") || strings.Contains(msg, "malformed"):
		code = finding.ErrCodeInvalidRecord
	}

	e := finding.CheckError{
		Check: check, Target: target, Code: code, Message: msg, Retryable: retryable,
	}
	if retryable {
		e.RetryAfterSeconds = 5
	}
	return e
}

// SortedCheckNames returns the names of the runner's checks, for reporting.
func (r *Runner) SortedCheckNames() []string {
	names := make([]string, 0, len(r.Checks))
	for _, c := range r.Checks {
		names = append(names, c.Describe().Name)
	}
	sort.Strings(names)
	return names
}

// String describes the runner's configuration, for progress and debug output.
func (r *Runner) String() string {
	return fmt.Sprintf("runner[checks=%s concurrency=%d check-concurrency=%d]",
		strings.Join(r.SortedCheckNames(), ","), r.Concurrency, r.CheckConcurrency)
}
