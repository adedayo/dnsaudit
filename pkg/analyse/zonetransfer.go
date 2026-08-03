package analyse

import (
	"sort"
	"strconv"
	"strings"

	"github.com/adedayo/vantage/pkg/finding"
)

// ZoneTransferAttempt is the outcome of one AXFR attempt against one server.
//
// Refused, Error and Transferred are deliberately three separate states rather
// than one boolean. A refusal is the control working; an error is the control
// unobserved; a transfer is the control absent. Collapsing any two of them
// would report one as another.
type ZoneTransferAttempt struct {
	// Nameserver is the server's hostname.
	Nameserver string
	// Address is the address queried.
	Address string
	// Answered reports that the server began streaming a zone.
	Answered bool
	// Transferred reports that records were actually disclosed.
	Transferred bool
	// Refused reports that the server declined, which is correct behaviour.
	Refused bool
	// RecordCount is how many records were disclosed.
	RecordCount int
	// Sample is a bounded excerpt retained as evidence.
	Sample []string
	// Serial is the SOA serial seen in the transfer.
	Serial uint32
	// HasSerial distinguishes serial zero from no SOA.
	HasSerial bool
	// Error is the transport or protocol failure, if any. A non-empty Error
	// with no transfer means nothing was established about this server.
	Error string
}

// ZoneTransferObservation is every attempt made for one zone.
type ZoneTransferObservation struct {
	// Domain is the zone.
	Domain string
	// Attempts is one entry per authoritative nameserver.
	Attempts []ZoneTransferAttempt
}

// partialTransferThreshold is the record count below which a transfer looks
// like a leak of metadata rather than a disclosure of the zone.
//
// A server that hands over only the SOA — which some do when misconfigured, and
// which an IXFR-style response can also produce — has disclosed the serial and
// the primary's name, but not the zone's contents. That is worth reporting and
// worth distinguishing, because the remediation and the urgency differ.
const partialTransferThreshold = 3

// ZoneTransfer evaluates AXFR attempts.
func ZoneTransfer(o Origin, obs ZoneTransferObservation) []finding.Finding {
	var findings []finding.Finding

	for _, a := range obs.Attempts {
		if !a.Transferred {
			// Refusals and failures alike produce no finding. A refusal is the
			// desired behaviour, and a failure established nothing: reporting
			// either would be reporting an absence of evidence as evidence.
			continue
		}

		evidence := []finding.Evidence{
			finding.ComputedEvidence("axfr.nameserver", a.Nameserver),
			finding.ComputedEvidence("axfr.records", strconv.Itoa(a.RecordCount)),
		}
		if a.HasSerial {
			evidence = append(evidence,
				finding.ComputedEvidence("axfr.serial", strconv.FormatUint(uint64(a.Serial), 10)))
		}
		if len(a.Sample) > 0 {
			evidence = append(evidence,
				finding.ComputedEvidence("axfr.sample", strings.Join(a.Sample, " | ")))
		}

		id := "SURF-AXFR-001"
		if a.RecordCount < partialTransferThreshold {
			id = "SURF-AXFR-002"
		}
		findings = append(findings, finding.New(id, o.Target, evidence...))
	}

	sort.SliceStable(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

// ZoneTransferAssessed reports whether any server actually answered, one way
// or the other.
//
// This is what separates "every server refused" from "no server could be
// reached". Both produce no findings, but only the first means the zone is
// protected: the second means nothing was learned at all, and reporting it as
// a clean result would be the most dangerous thing this check could do.
// Outbound TCP port 53 is blocked on many corporate networks, so the
// unassessed case is common rather than exotic.
func ZoneTransferAssessed(obs ZoneTransferObservation) bool {
	for _, a := range obs.Attempts {
		if a.Refused || a.Transferred || a.Answered {
			return true
		}
	}
	return false
}

// ZoneTransferRecords renders the attempts for the result's record list, so a
// reader can see which servers were asked and what each of them said.
//
// Servers that refused are listed explicitly. A check that reports only its
// findings would show nothing at all for a correctly configured zone, leaving
// a reader unable to tell a passing test from one that never ran.
func ZoneTransferRecords(obs ZoneTransferObservation) []string {
	records := make([]string, 0, len(obs.Attempts))
	for _, a := range obs.Attempts {
		line := a.Nameserver
		switch {
		case a.Transferred:
			line += " transferred " + strconv.Itoa(a.RecordCount) + " records"
		case a.Refused:
			line += " refused"
		case a.Error != "":
			line += " no answer (" + a.Error + ")"
		default:
			line += " no answer"
		}
		records = append(records, line)
	}
	return records
}
