package analyse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseMX(t *testing.T) {
	tests := map[string]struct {
		records []string
		want    []MXHost
	}{
		"trailing dot is stripped": {
			records: []string{"10 mail.example.com."},
			want:    []MXHost{{Preference: 10, Host: "mail.example.com"}},
		},
		"null MX keeps its dot": {
			records: []string{"0 ."},
			want:    []MXHost{{Preference: 0, Host: "."}},
		},
		"multiple hosts": {
			records: []string{"10 a.example.com.", "20 b.example.com."},
			want: []MXHost{
				{Preference: 10, Host: "a.example.com"},
				{Preference: 20, Host: "b.example.com"},
			},
		},
		"blank records are skipped":      {records: []string{"", "  "}, want: nil},
		"unparseable preference skipped": {records: []string{"x mail.example.com"}, want: nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, ParseMX(tc.records))
		})
	}
}

func TestMXNullMXSuppressesHygieneRules(t *testing.T) {
	// A null MX is a deliberate, complete statement that the domain accepts no
	// mail. Reporting "only one MX" or "does not resolve" against it would
	// penalise exactly the configuration RFC 7505 asks for.
	hosts := []MXHost{{Preference: 0, Host: "."}}
	got := MX(Origin{Target: "example.com"}, hosts, true)
	assert.Empty(t, got)
}

func TestMXNoRecords(t *testing.T) {
	t.Run("with an address record the null MX is worth having", func(t *testing.T) {
		got := ids(MX(Origin{Target: "example.com"}, nil, true))
		assert.Equal(t, []string{"DNSA-MX-003"}, got)
	})

	t.Run("without one there is nothing to fall back to", func(t *testing.T) {
		got := MX(Origin{Target: "example.com"}, nil, false)
		assert.Empty(t, got)
	})
}

func TestMXUnresolvableHost(t *testing.T) {
	hosts := []MXHost{
		{Preference: 10, Host: "good.example.com", Resolves: true},
		{Preference: 20, Host: "typo.example.com", Resolves: false},
	}
	got := ids(MX(Origin{Target: "example.com"}, hosts, true))
	assert.Equal(t, []string{"DNSA-MX-001"}, got)
}

// TestMXUnresolvableCNAMEReportsOneDefect guards against double-reporting: a
// host that does not resolve should not also be diagnosed as a bad CNAME.
func TestMXUnresolvableCNAMEReportsOneDefect(t *testing.T) {
	hosts := []MXHost{
		{Preference: 10, Host: "a.example.com", Resolves: true},
		{Preference: 20, Host: "b.example.com", Resolves: false, IsCNAME: true},
	}
	got := ids(MX(Origin{Target: "example.com"}, hosts, true))
	assert.Equal(t, []string{"DNSA-MX-001"}, got)
}

func TestMXCNAMETarget(t *testing.T) {
	hosts := []MXHost{
		{Preference: 10, Host: "a.example.com", Resolves: true, IsCNAME: true},
		{Preference: 20, Host: "b.example.com", Resolves: true},
	}
	got := ids(MX(Origin{Target: "example.com"}, hosts, true))
	assert.Equal(t, []string{"DNSA-MX-002"}, got)
}

func TestMXSingleExchanger(t *testing.T) {
	hosts := []MXHost{{Preference: 10, Host: "mail.example.com", Resolves: true}}
	got := ids(MX(Origin{Target: "example.com"}, hosts, true))
	assert.Equal(t, []string{"DNSA-MX-004"}, got)
}

func TestMXHealthyConfigurationIsClean(t *testing.T) {
	hosts := []MXHost{
		{Preference: 10, Host: "a.example.com", Resolves: true},
		{Preference: 20, Host: "b.example.com", Resolves: true},
	}
	assert.Empty(t, MX(Origin{Target: "example.com"}, hosts, true))
}

func TestMXHostIsNull(t *testing.T) {
	tests := map[string]struct {
		host MXHost
		want bool
	}{
		"canonical null MX":    {host: MXHost{Preference: 0, Host: "."}, want: true},
		"empty host":           {host: MXHost{Preference: 0, Host: ""}, want: true},
		"dot at non-zero pref": {host: MXHost{Preference: 10, Host: "."}, want: false},
		"real host":            {host: MXHost{Preference: 0, Host: "mail.example.com"}, want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.host.IsNull())
		})
	}
}
