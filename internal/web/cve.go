package web

import (
	"regexp"
	"strings"
)

var cvePattern = regexp.MustCompile(`(?i)^CVE-[0-9]{4}-[0-9]{4,}$`)

func cveURL(value string) string {
	cve := strings.ToUpper(strings.TrimSpace(value))
	if !cvePattern.MatchString(cve) {
		return ""
	}
	return "https://nvd.nist.gov/vuln/detail/" + cve
}
