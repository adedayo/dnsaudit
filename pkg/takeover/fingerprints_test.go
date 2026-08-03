package takeover_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/dnsaudit/pkg/takeover"
)

// The embedded database is the evidence behind Critical findings, so its
// integrity is asserted here rather than trusted.
func TestEmbeddedDatabaseIsValid(t *testing.T) {
	db, err := takeover.Load()
	require.NoError(t, err)
	assert.Equal(t, takeover.SupportedSchemaVersion, db.SchemaVersion)
	assert.NotEmpty(t, db.Fingerprints)
	assert.NotEmpty(t, db.Provenance)
	assert.NoError(t, db.Validate())
}

func TestMatch(t *testing.T) {
	db, err := takeover.Load()
	require.NoError(t, err)

	cases := map[string]string{
		"mybucket.s3.amazonaws.com":     "AWS S3",
		"example.github.io":             "GitHub Pages",
		"warm-fjord-1234.herokuapp.com": "Heroku",
		"contoso.azurewebsites.net":     "Microsoft Azure",
	}
	for target, service := range cases {
		f, ok := db.Match(target)
		require.True(t, ok, target)
		assert.Equal(t, service, f.Service, target)
	}

	_, ok := db.Match("ns1.provider.example")
	assert.False(t, ok)
	_, ok = db.Match("")
	assert.False(t, ok)
}

// A name merely containing a pattern is not a match: "notgithub.io" belongs to
// somebody else entirely, and a Critical finding on it would be defamatory as
// well as wrong.
func TestMatchRequiresALabelBoundary(t *testing.T) {
	db, err := takeover.Load()
	require.NoError(t, err)

	_, ok := db.Match("evilgithub.io")
	assert.False(t, ok)

	_, ok = db.Match("example.github.io")
	assert.True(t, ok)
}

func TestValidateRejectsMalformedDatabases(t *testing.T) {
	cases := map[string]string{
		"unsupported schema": `{"schema_version":99,"provenance":"p","fingerprints":[]}`,
		"no provenance":      `{"schema_version":1,"provenance":"","fingerprints":[]}`,
		"empty":              `{"schema_version":1,"provenance":"p","fingerprints":[]}`,
		"no reference": `{"schema_version":1,"provenance":"p","fingerprints":[
			{"service":"X","cname_patterns":[".x.example"],"nxdomain":true,"status":"vulnerable"}]}`,
		"unknown status": `{"schema_version":1,"provenance":"p","fingerprints":[
			{"service":"X","cname_patterns":[".x.example"],"nxdomain":true,"status":"maybe","reference":"r"}]}`,
		// A fingerprint detectable by neither route could only ever produce a
		// guess dressed as a finding.
		"undetectable": `{"schema_version":1,"provenance":"p","fingerprints":[
			{"service":"X","cname_patterns":[".x.example"],"nxdomain":false,"status":"vulnerable","reference":"r"}]}`,
		"duplicate pattern": `{"schema_version":1,"provenance":"p","fingerprints":[
			{"service":"X","cname_patterns":[".x.example"],"nxdomain":true,"status":"vulnerable","reference":"r"},
			{"service":"Y","cname_patterns":[".x.example"],"nxdomain":true,"status":"vulnerable","reference":"r"}]}`,
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := takeover.Parse([]byte(data))
			assert.Error(t, err)
		})
	}
}
