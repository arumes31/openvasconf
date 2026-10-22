package config

import (
	"encoding/base64"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDecodeEncryptionKey(t *testing.T) {
	raw := []byte("0123456789abcdef0123456789abcdef")
	tests := []struct {
		name    string
		value   string
		wantLen int
		wantErr bool
	}{
		{name: "unset"},
		{name: "raw", value: string(raw), wantLen: 32},
		{name: "base64", value: base64.StdEncoding.EncodeToString(raw), wantLen: 32},
		{name: "wrong length", value: "too-short", wantErr: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			key, err := decodeEncryptionKey(testCase.value)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("decodeEncryptionKey() error = %v, wantErr %t", err, testCase.wantErr)
			}
			if len(key) != testCase.wantLen {
				t.Errorf("key length = %d, want %d", len(key), testCase.wantLen)
			}
		})
	}
}

func TestLoadReportFetchTimeout(t *testing.T) {
	t.Setenv(adminSecretValueEnv, "admin-test-password")
	t.Setenv("OPENVASCONF_ADMIN_PASSWORD_FILE", "")
	t.Setenv("OPENVASCONF_REPORT_FETCH_TIMEOUT", "7m")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ReportFetchTimeout != 7*time.Minute {
		t.Errorf("ReportFetchTimeout = %v, want 7m", cfg.ReportFetchTimeout)
	}
}

func TestNativeInteger(t *testing.T) {
	t.Setenv("OPENVASCONF_TEST_INTEGER", " 42 ")

	got, err := nativeInteger("OPENVASCONF_TEST_INTEGER", 7)
	if err != nil {
		t.Fatalf("nativeInteger() error = %v", err)
	}
	if got != 42 {
		t.Errorf("nativeInteger() = %d, want 42", got)
	}
}

func TestNativeIntegerUsesFallback(t *testing.T) {
	t.Setenv("OPENVASCONF_TEST_INTEGER", "")

	got, err := nativeInteger("OPENVASCONF_TEST_INTEGER", 7)
	if err != nil {
		t.Fatalf("nativeInteger() error = %v", err)
	}
	if got != 7 {
		t.Errorf("nativeInteger() = %d, want 7", got)
	}
}

func TestNativeIntegerRejectsPlatformOverflow(t *testing.T) {
	overflow := strconv.FormatUint(uint64(math.MaxInt)+1, 10)
	t.Setenv("OPENVASCONF_TEST_INTEGER", overflow)

	_, err := nativeInteger("OPENVASCONF_TEST_INTEGER", 7)
	if err == nil {
		t.Fatal("nativeInteger() error = nil, want overflow error")
	}
	if !strings.Contains(err.Error(), "OPENVASCONF_TEST_INTEGER") {
		t.Errorf("nativeInteger() error = %q, want environment key", err)
	}
}

func TestLoadSecurityOptions(t *testing.T) {
	t.Setenv(adminSecretValueEnv, "admin-test-password")
	t.Setenv("OPENVASCONF_ADMIN_PASSWORD_FILE", "")
	t.Setenv("OPENVASCONF_SESSION_IDLE_TIMEOUT", "")
	t.Setenv("OPENVASCONF_TRUST_PROXY_CLIENT_IP", "")
	t.Setenv("OPENVASCONF_HOOKWISE_ALLOW_INSECURE_HTTP", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.SessionIdleTimeout != 2*time.Hour || cfg.TrustProxyClientIP || cfg.HookwiseAllowInsecureHTTP {
		t.Errorf("defaults = idle %v, trust client ip %t, allow http %t",
			cfg.SessionIdleTimeout, cfg.TrustProxyClientIP, cfg.HookwiseAllowInsecureHTTP)
	}

	t.Setenv("OPENVASCONF_SESSION_IDLE_TIMEOUT", "30m")
	t.Setenv("OPENVASCONF_TRUST_PROXY_CLIENT_IP", "true")
	t.Setenv("OPENVASCONF_HOOKWISE_ALLOW_INSECURE_HTTP", "true")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.SessionIdleTimeout != 30*time.Minute || !cfg.TrustProxyClientIP || !cfg.HookwiseAllowInsecureHTTP {
		t.Errorf("overrides = idle %v, trust client ip %t, allow http %t",
			cfg.SessionIdleTimeout, cfg.TrustProxyClientIP, cfg.HookwiseAllowInsecureHTTP)
	}

	t.Setenv("OPENVASCONF_SESSION_IDLE_TIMEOUT", "-1m")
	if _, err := Load(); err == nil {
		t.Error("Load() with negative idle timeout error = nil")
	}
}
