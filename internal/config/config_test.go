package config

import (
	"math"
	"strconv"
	"strings"
	"testing"
)

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
