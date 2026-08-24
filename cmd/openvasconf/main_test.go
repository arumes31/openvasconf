package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestValidateConfigValid(t *testing.T) {
	t.Setenv("OPENVASCONF_ADMIN_PASSWORD", "correct horse battery staple")
	t.Setenv("OPENVASCONF_ADMIN_PASSWORD_FILE", "")
	t.Setenv("OPENVASCONF_GMP_PASSWORD_FILE", "")
	t.Setenv("OPENVASCONF_RECONCILE_INTERVAL", "1m")
	t.Setenv("OPENVASCONF_EXTERNAL_TIMEOUT", "15s")
	t.Setenv("OPENVASCONF_SESSION_LIFETIME", "12h")
	t.Setenv("OPENVASCONF_TIMEZONE", "Europe/Vienna")

	var output bytes.Buffer
	if code := validateConfig(&output); code != 0 {
		t.Fatalf("validateConfig() = %d, want 0: %s", code, output.String())
	}
	if !strings.Contains(output.String(), "configuration valid") {
		t.Errorf("output = %q, want a valid confirmation", output.String())
	}
}

func TestValidateConfigReportsAllProblems(t *testing.T) {
	t.Setenv("OPENVASCONF_ADMIN_PASSWORD", "short")
	t.Setenv("OPENVASCONF_ADMIN_PASSWORD_FILE", "")
	t.Setenv("OPENVASCONF_GMP_PASSWORD_FILE", "/definitely/missing/secret")
	t.Setenv("OPENVASCONF_RECONCILE_INTERVAL", "not-a-duration")
	t.Setenv("OPENVASCONF_SECURE_COOKIES", "not-a-bool")
	t.Setenv("OPENVASCONF_TIMEZONE", "Not/AZone")

	var output bytes.Buffer
	code := validateConfig(&output)
	if code != 1 {
		t.Fatalf("validateConfig() = %d, want 1", code)
	}
	text := output.String()
	for _, expected := range []string{
		"admin password must contain at least 12 characters",
		"OPENVASCONF_GMP_PASSWORD_FILE",
		"OPENVASCONF_RECONCILE_INTERVAL",
		"OPENVASCONF_SECURE_COOKIES",
		"OPENVASCONF_TIMEZONE",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("output does not report %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "short") && strings.Contains(text, "admin password is required") {
		t.Errorf("output leaked a secret value:\n%s", text)
	}
}
