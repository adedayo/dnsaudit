package analyse

import (
	"os"
	"strings"
	"testing"
)

func TestParseWeakKeyStillWorks(t *testing.T) {
	b, err := os.ReadFile("/tmp/k512.b64")
	if err != nil {
		t.Fatal(err)
	}
	k := ParseDKIM("s1", "v=DKIM1; k=rsa; p="+strings.TrimSpace(string(b)))
	t.Logf("valid=%v bits=%d reason=%q", k.Valid, k.Bits, k.Reason)
	if k.Bits != 512 {
		t.Fatalf("REGRESSION: a real 512-bit key no longer reports 512 bits (got %d)", k.Bits)
	}
}
