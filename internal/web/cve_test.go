package web

import "testing"

func TestCVEURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "canonical", value: "CVE-2026-12345", want: "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"},
		{name: "normalized", value: " cve-2021-1234 ", want: "https://nvd.nist.gov/vuln/detail/CVE-2021-1234"},
		{name: "reject short sequence", value: "CVE-2026-123", want: ""},
		{name: "reject injected suffix", value: "CVE-2026-1234?x=1", want: ""},
		{name: "reject reference text", value: "GHSA-abcd", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := cveURL(test.value); got != test.want {
				t.Errorf("cveURL(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}
