package networkplan

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestBuild(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		input             Input
		expectedPrivate   int
		expectedWAN       int
		expectedAddresses uint64
		wantError         string
	}{
		{
			name: "approved customer example",
			input: Input{
				CustomerName: "testcomp1",
				Networks:     []string{"10.1.0.0/16", "192.168.10.0", "7.7.7.7/32"},
			},
			expectedPrivate:   18,
			expectedWAN:       1,
			expectedAddresses: 65_538,
		},
		{
			name: "overlap is scanned once",
			input: Input{
				CustomerName: "overlap",
				Networks:     []string{"10.0.0.0/24", "10.0.0.1", "10.0.0.0/25"},
			},
			expectedPrivate:   1,
			expectedAddresses: 256,
		},
		{
			name: "documentation range rejected",
			input: Input{
				CustomerName: "invalid",
				Networks:     []string{"192.0.2.1"},
			},
			wantError: "special-use",
		},
		{
			name: "ipv6 rejected",
			input: Input{
				CustomerName: "invalid",
				Networks:     []string{"2001:db8::/32"},
			},
			wantError: "not ipv4",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan, err := Build(test.input)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("Build() error = %v, want containing %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}

			var privateCount int
			var wanCount int
			var addressCount uint64
			for _, target := range plan.Targets {
				if target.AddressCount > DefaultMaxAddresses {
					t.Errorf("target %s contains %d addresses", target.Name, target.AddressCount)
				}
				switch target.Class {
				case ClassPrivateIP:
					privateCount++
				case ClassWAN:
					wanCount++
				default:
					t.Errorf("target %s has unknown class %q", target.Name, target.Class)
				}
				addressCount += target.AddressCount
			}

			if privateCount != test.expectedPrivate {
				t.Errorf("private targets = %d, want %d", privateCount, test.expectedPrivate)
			}
			if wanCount != test.expectedWAN {
				t.Errorf("wan targets = %d, want %d", wanCount, test.expectedWAN)
			}
			if addressCount != test.expectedAddresses {
				t.Errorf("address count = %d, want %d", addressCount, test.expectedAddresses)
			}
		})
	}
}

func TestBuildPacksExactLimit(t *testing.T) {
	t.Parallel()

	networks := make([]string, 0, 271)
	for octet := range 15 {
		networks = append(networks, netip.PrefixFrom(
			netip.AddrFrom4([4]byte{192, 168, byte(octet), 0}),
			24,
		).String())
	}
	for host := range 255 {
		networks = append(networks, netip.AddrFrom4(
			[4]byte{192, 168, 15, byte(host)},
		).String())
	}
	networks = append(networks, "192.168.16.0/24")

	plan, err := Build(Input{CustomerName: "boundary", Networks: networks})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(plan.Targets) != 2 {
		t.Fatalf("target count = %d, want 2", len(plan.Targets))
	}
	if plan.Targets[0].AddressCount != 4095 {
		t.Errorf("first target address count = %d, want 4095", plan.Targets[0].AddressCount)
	}
	if plan.Targets[1].AddressCount != 256 {
		t.Errorf("second target address count = %d, want 256", plan.Targets[1].AddressCount)
	}
}

func TestBuildRejectsExcessiveReconciliationWork(t *testing.T) {
	t.Parallel()

	_, err := Build(Input{CustomerName: "oversized", Networks: []string{"10.0.0.0/8"}})
	if err == nil || !strings.Contains(err.Error(), "target count") {
		t.Fatalf("Build() error = %v, want target count safety limit", err)
	}
}

func TestBuildPrefixBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		network         string
		addresses       uint64
		expectedTargets int
	}{
		{name: "host", network: "10.0.0.1/32", addresses: 1, expectedTargets: 1},
		{name: "point to point", network: "10.0.0.0/31", addresses: 2, expectedTargets: 1},
		{name: "half class c", network: "10.0.0.0/25", addresses: 128, expectedTargets: 1},
		{name: "class c", network: "10.0.0.0/24", addresses: 256, expectedTargets: 1},
		{name: "two class c", network: "10.0.0.0/23", addresses: 512, expectedTargets: 1},
		{name: "exactly 4096", network: "10.0.0.0/20", addresses: 4096, expectedTargets: 2},
		{name: "class b", network: "10.1.0.0/16", addresses: 65_536, expectedTargets: 18},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan, err := Build(Input{CustomerName: "boundary", Networks: []string{test.network}})
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if len(plan.Targets) != test.expectedTargets {
				t.Fatalf("target count = %d, want %d", len(plan.Targets), test.expectedTargets)
			}
			var addresses uint64
			for _, target := range plan.Targets {
				if target.AddressCount > DefaultMaxAddresses {
					t.Errorf("target contains %d addresses", target.AddressCount)
				}
				addresses += target.AddressCount
			}
			if addresses != test.addresses {
				t.Errorf("address count = %d, want %d", addresses, test.addresses)
			}
		})
	}
}

func TestBuildIsStableAcrossInputOrder(t *testing.T) {
	t.Parallel()

	forward, err := Build(Input{
		CustomerName: "stable",
		Networks:     []string{"10.2.0.0/24", "10.1.0.0/24", "8.8.8.8"},
	})
	if err != nil {
		t.Fatalf("Build(forward) error = %v", err)
	}
	reverse, err := Build(Input{
		CustomerName: "stable",
		Networks:     []string{"8.8.8.8", "10.1.0.0/24", "10.2.0.0/24"},
	})
	if err != nil {
		t.Fatalf("Build(reverse) error = %v", err)
	}
	if !slices.EqualFunc(forward.Targets, reverse.Targets, func(left, right Target) bool {
		return left.Name == right.Name && left.Hash == right.Hash
	}) {
		t.Errorf("plans differ:\nforward=%#v\nreverse=%#v", forward.Targets, reverse.Targets)
	}
}

func TestParseImplicitHost(t *testing.T) {
	t.Parallel()

	prefix, err := Parse("192.168.10.0")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if prefix.String() != "192.168.10.0/32" {
		t.Errorf("prefix = %s, want 192.168.10.0/32", prefix)
	}
}

func TestAnalyzeReportsDuplicatesOverlapsAndUniqueAddresses(t *testing.T) {
	t.Parallel()
	analysis, err := Analyze(Input{
		CustomerName: "diagnostics",
		Networks:     []string{"10.0.0.0/24", "10.0.0.1", "10.0.0.0/24", "8.8.8.8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if analysis.UniqueAddresses != 257 {
		t.Fatalf("unique addresses = %d, want 257", analysis.UniqueAddresses)
	}
	kinds := map[string]bool{}
	for _, diagnostic := range analysis.Diagnostics {
		kinds[diagnostic.Kind] = true
	}
	if !kinds["duplicate"] || !kinds["overlap"] {
		t.Fatalf("diagnostics = %#v", analysis.Diagnostics)
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"10.0.0.0/8", "7.7.7.7", "", "2001:db8::1", "bad"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		prefix, err := Parse(input)
		if err != nil {
			return
		}
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			t.Fatalf("Parse(%q) returned invalid prefix %s", input, prefix)
		}
	})
}
