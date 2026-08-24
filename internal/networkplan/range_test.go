package networkplan

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestExpandRangeToMinimalCIDRs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"single address", "192.168.1.10-192.168.1.10", []string{"192.168.1.10/32"}},
		{"aligned block", "10.0.0.0-10.0.0.255", []string{"10.0.0.0/24"}},
		{"aligned large block", "10.0.0.0-10.0.1.255", []string{"10.0.0.0/23"}},
		{
			"unaligned split",
			"10.0.0.1-10.0.0.9",
			[]string{"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/30", "10.0.0.8/31"},
		},
		{"entire space", "0.0.0.0-255.255.255.255", []string{"0.0.0.0/0"}},
		{"first address", "0.0.0.0-0.0.0.0", []string{"0.0.0.0/32"}},
		{"last address", "255.255.255.255-255.255.255.255", []string{"255.255.255.255/32"}},
		{
			"tail of space",
			"255.255.255.254-255.255.255.255",
			[]string{"255.255.255.254/31"},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			prefixes, err := Expand(testCase.input)
			if err != nil {
				t.Fatalf("Expand() error = %v", err)
			}
			if len(prefixes) != len(testCase.want) {
				t.Fatalf("Expand() = %v, want %v", prefixes, testCase.want)
			}
			for index, want := range testCase.want {
				if prefixes[index].String() != want {
					t.Errorf("Expand()[%d] = %s, want %s", index, prefixes[index], want)
				}
			}
		})
	}
}

func TestExpandRangePreservesExactCoverage(t *testing.T) {
	t.Parallel()

	cases := []string{
		"10.3.7.5-10.3.7.200",
		"192.168.0.1-192.168.255.254",
		"8.8.8.8-8.8.8.8",
		"10.0.0.1-10.255.255.254",
	}
	for _, input := range cases {
		prefixes, err := Expand(input)
		if err != nil {
			t.Fatalf("Expand(%s) error = %v", input, err)
		}
		var start, end uint64
		if _, err := parseRangeBounds(input, &start, &end); err != nil {
			t.Fatal(err)
		}
		var covered uint64
		cursor := start
		for _, prefix := range prefixes {
			first := uint64(ipv4Number(prefix.Addr()))
			if first != cursor {
				t.Fatalf("Expand(%s) has a gap before %s", input, prefix)
			}
			count := addressCount(prefix)
			covered += count
			cursor += count
		}
		if covered != end-start+1 {
			t.Errorf("Expand(%s) covers %d addresses, want %d", input, covered, end-start+1)
		}
	}
}

func parseRangeBounds(input string, start, end *uint64) (bool, error) {
	parts := strings.Split(input, "-")
	if len(parts) != 2 {
		return false, errors.New("not a range")
	}
	startAddr, err := netip.ParseAddr(parts[0])
	if err != nil {
		return false, err
	}
	endAddr, err := netip.ParseAddr(parts[1])
	if err != nil {
		return false, err
	}
	*start = uint64(ipv4Number(startAddr))
	*end = uint64(ipv4Number(endAddr))
	return true, nil
}

func TestExpandRejectsInvalidRanges(t *testing.T) {
	t.Parallel()

	cases := []string{
		"10.0.0.9-10.0.0.1",
		"10.0.0.1-",
		"-10.0.0.1",
		"10.0.0.1-10.0.0.2-10.0.0.3",
		"10.0.0.1-not-an-ip",
		"fd00::1-fd00::9",
		"10.0.0.1-fd00::9",
	}
	for _, input := range cases {
		if _, err := Expand(input); err == nil {
			t.Errorf("Expand(%q) = nil error, want rejection", input)
		}
	}
}

func TestExpandNonRangeInputsUnchanged(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"192.168.10.0":    "192.168.10.0/32",
		"192.168.10.7/32": "192.168.10.7/32",
		"10.1.2.3/24":     "10.1.2.0/24",
	}
	for input, want := range cases {
		prefixes, err := Expand(input)
		if err != nil {
			t.Fatalf("Expand(%q) error = %v", input, err)
		}
		if len(prefixes) != 1 || prefixes[0].String() != want {
			t.Errorf("Expand(%q) = %v, want %s", input, prefixes, want)
		}
	}
}

func TestBuildAcceptsRangeInputs(t *testing.T) {
	t.Parallel()

	plan, err := Build(Input{
		CustomerName: "ranges",
		Networks:     []string{"192.168.5.10-192.168.5.12", "8.8.8.8-8.8.8.9"},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(plan.Targets) != 2 {
		t.Fatalf("target count = %d, want private and WAN targets", len(plan.Targets))
	}
	for _, target := range plan.Targets {
		switch target.Class {
		case ClassPrivateIP:
			if target.AddressCount != 3 {
				t.Errorf("private addresses = %d, want 3", target.AddressCount)
			}
		case ClassWAN:
			if target.AddressCount != 2 {
				t.Errorf("wan addresses = %d, want 2", target.AddressCount)
			}
		}
	}
}

func TestBuildRejectsSpecialUseRange(t *testing.T) {
	t.Parallel()

	if _, err := Build(Input{CustomerName: "bad", Networks: []string{"224.0.0.1-224.0.0.9"}}); err == nil {
		t.Fatal("Build() accepted a multicast range")
	}
}
