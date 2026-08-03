package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func axfrIDs(t *testing.T, obs ZoneTransferObservation) []string {
	t.Helper()
	var ids []string
	for _, f := range ZoneTransfer(Origin{Target: obs.Domain}, obs) {
		ids = append(ids, f.ID)
	}
	return ids
}

func TestZoneTransferDisclosure(t *testing.T) {
	obs := ZoneTransferObservation{
		Domain: "example.com",
		Attempts: []ZoneTransferAttempt{
			{Nameserver: "ns1.example.com", Refused: true},
			{
				Nameserver: "ns2.example.com", Answered: true, Transferred: true,
				RecordCount: 412, Serial: 2026080301, HasSerial: true,
				Sample: []string{"example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 2 3 4 5"},
			},
		},
	}

	findings := ZoneTransfer(Origin{Target: "example.com"}, obs)
	require.Len(t, findings, 1)
	assert.Equal(t, "SURF-AXFR-001", findings[0].ID)
}

// One well-configured server does not protect a zone that another will hand
// over, so a refusal must never mask a disclosure elsewhere.
func TestZoneTransferRefusalDoesNotMaskDisclosure(t *testing.T) {
	obs := ZoneTransferObservation{
		Domain: "example.com",
		Attempts: []ZoneTransferAttempt{
			{Nameserver: "ns1.example.com", Refused: true},
			{Nameserver: "ns2.example.com", Refused: true},
			{Nameserver: "ns3.example.com", Answered: true, Transferred: true, RecordCount: 88},
		},
	}
	assert.Equal(t, []string{"SURF-AXFR-001"}, axfrIDs(t, obs))
}

// Refusal is the control working. Reporting it would invert the check.
func TestZoneTransferRefusalIsSilent(t *testing.T) {
	obs := ZoneTransferObservation{
		Domain: "example.com",
		Attempts: []ZoneTransferAttempt{
			{Nameserver: "ns1.example.com", Refused: true},
			{Nameserver: "ns2.example.com", Refused: true},
		},
	}
	assert.Empty(t, axfrIDs(t, obs))
}

// A server we could not reach established nothing. Reporting an absence of
// evidence as evidence of absence — in either direction — is the defect this
// project has hit most often.
func TestZoneTransferUnreachableServerIsSilent(t *testing.T) {
	obs := ZoneTransferObservation{
		Domain: "example.com",
		Attempts: []ZoneTransferAttempt{
			{Nameserver: "ns1.example.com", Error: "dial tcp: i/o timeout"},
		},
	}
	assert.Empty(t, axfrIDs(t, obs))
}

// Metadata-only disclosure is a different finding with different urgency: the
// serial and primary leak, but the estate does not.
func TestZoneTransferPartialDisclosure(t *testing.T) {
	obs := ZoneTransferObservation{
		Domain: "example.com",
		Attempts: []ZoneTransferAttempt{{
			Nameserver: "ns1.example.com", Answered: true, Transferred: true,
			RecordCount: 1, Serial: 2026080301, HasSerial: true,
		}},
	}
	assert.Equal(t, []string{"SURF-AXFR-002"}, axfrIDs(t, obs))
}

// "Every server refused" and "no server could be reached" both yield no
// findings, but only the first means the zone is protected. Conflating them
// reports an untested zone as a clean one.
func TestZoneTransferAssessed(t *testing.T) {
	refused := ZoneTransferObservation{Attempts: []ZoneTransferAttempt{
		{Nameserver: "ns1.example.com", Refused: true},
	}}
	assert.True(t, ZoneTransferAssessed(refused))

	unreachable := ZoneTransferObservation{Attempts: []ZoneTransferAttempt{
		{Nameserver: "ns1.example.com", Error: "i/o timeout"},
		{Nameserver: "ns2.example.com", Error: "connection refused by firewall"},
	}}
	assert.False(t, ZoneTransferAssessed(unreachable))

	// One reachable server is enough to have assessed something.
	mixed := ZoneTransferObservation{Attempts: []ZoneTransferAttempt{
		{Nameserver: "ns1.example.com", Error: "i/o timeout"},
		{Nameserver: "ns2.example.com", Refused: true},
	}}
	assert.True(t, ZoneTransferAssessed(mixed))
}

// A correctly configured zone must still show what was tested, otherwise a
// reader cannot tell a passing check from one that never ran.
func TestZoneTransferRecordsShowEveryServer(t *testing.T) {
	obs := ZoneTransferObservation{
		Domain: "example.com",
		Attempts: []ZoneTransferAttempt{
			{Nameserver: "ns1.example.com", Refused: true},
			{Nameserver: "ns2.example.com", Error: "i/o timeout"},
			{Nameserver: "ns3.example.com", Answered: true, Transferred: true, RecordCount: 5},
		},
	}

	records := ZoneTransferRecords(obs)
	require.Len(t, records, 3)
	assert.Contains(t, records[0], "refused")
	assert.Contains(t, records[1], "no answer")
	assert.Contains(t, records[2], "transferred 5 records")
}
