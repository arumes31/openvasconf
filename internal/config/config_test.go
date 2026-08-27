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
