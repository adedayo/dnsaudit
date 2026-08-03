package audit

import "fmt"

// Vantage is the position an assessment is carried out from. It is the axis
// along which this tool's scope is defined: the same target presents a
// different surface to someone on the public internet than to someone who has
// already reached an internal network, and a finding is only meaningful when
// the vantage it was observed from is known.
//
// Only VantageExternal is implemented. The type exists from the first release
// so that internal support arrives as a new value rather than as a new flag,
// and so that a result records the vantage it was produced from even while
// there is just the one.
type Vantage string

const (
	// VantageExternal assesses what is reachable and knowable from the public
	// internet, with no privileged position and no credentials.
	VantageExternal Vantage = "external"

	// VantageInternal assesses what is exposed to someone who has already
	// reached an internal network, modelling a threat actor who has gained a
	// foothold on an internal service.
	//
	// Not yet implemented; declared so the vocabulary is fixed.
	VantageInternal Vantage = "internal"
)

// DefaultVantage is the vantage assumed when none is given.
const DefaultVantage = VantageExternal

// Vantages returns the vantages that can currently be assessed from, for use
// in help text and validation messages. VantageInternal is deliberately
// excluded: offering a value that cannot be run would be a false promise.
func Vantages() []string {
	return []string{string(VantageExternal)}
}

// ParseVantage validates a vantage supplied on the command line.
//
// A recognised-but-unimplemented vantage is reported differently from an
// unrecognised one. "internal is not implemented yet" tells the caller their
// intent was understood and the capability is absent; "unknown vantage" would
// suggest a typo and send them looking for the right spelling.
func ParseVantage(s string) (Vantage, error) {
	switch Vantage(s) {
	case VantageExternal:
		return VantageExternal, nil
	case VantageInternal:
		return "", fmt.Errorf(
			"vantage point %q is not implemented yet; only %q is currently supported",
			s, VantageExternal)
	default:
		return "", fmt.Errorf("unknown vantage point %q; supported: %v", s, Vantages())
	}
}
