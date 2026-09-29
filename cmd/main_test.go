package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/netstar-labs/sanitize"
)

// TestDecideRequiresOkay is the regression for the A1-audit finding: r.TLD > 0
// alone used to be treated as "valid registrable domain," but TLD is set
// before Okay is computed, so an otherwise-invalid host (e.g. one over the
// length caps) that still matches a tld would print to stdout as if valid.
func TestDecideRequiresOkay(t *testing.T) {
	// matched a tld, but failed a later check (e.g. length cap) -> not valid.
	if decide(sanitize.Result{TLD: 5, Okay: false}, false, false) {
		t.Error("decide(TLD>0, Okay=false) = true, want false")
	}
	// matched a tld and passed every check -> valid.
	if !decide(sanitize.Result{TLD: 5, Okay: true}, false, false) {
		t.Error("decide(TLD>0, Okay=true) = false, want true")
	}
	// IP always follows keepIP regardless of TLD/Okay.
	if decide(sanitize.Result{IP: true, Okay: true}, false, false) {
		t.Error("decide(IP, keepIP=false) = true, want false")
	}
	if !decide(sanitize.Result{IP: true, Okay: true}, true, false) {
		t.Error("decide(IP, keepIP=true) = false, want true")
	}
}

func TestEnvBool(t *testing.T) {
	const key = "SANITIZE_CMD_TEST_ENVBOOL"
	defer os.Unsetenv(key)
	for _, tc := range []struct {
		val  string
		want bool
	}{
		{"on", true}, {"true", true}, {"1", true},
		{"", false}, {"off", false}, {"0", false}, {"yes", false},
	} {
		os.Setenv(key, tc.val)
		if got := envBool(key); got != tc.want {
			t.Errorf("envBool(%q) = %v, want %v", tc.val, got, tc.want)
		}
	}
}

func TestRoute(t *testing.T) {
	dir := t.TempDir()
	good, err := os.Create(dir + "/good")
	if err != nil {
		t.Fatal(err)
	}
	bad, err := os.Create(dir + "/bad")
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	defer bad.Close()

	route(true, good, bad, "example.com")
	route(false, good, bad, "rejected.example")

	goodContent, _ := os.ReadFile(good.Name())
	badContent, _ := os.ReadFile(bad.Name())
	if !bytes.Contains(goodContent, []byte("example.com")) {
		t.Errorf("route(true, ...) did not write to good: %q", goodContent)
	}
	if !bytes.Contains(badContent, []byte("rejected.example")) {
		t.Errorf("route(false, ...) did not write to bad: %q", badContent)
	}
}
