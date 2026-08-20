package networkplan

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode"
)

const (
	DefaultMaxAddresses = uint64(4095)
	maxExpandedPrefixes = 65_536
	maxTargetsPerPlan   = 1_024
)

type Class string

const (
	ClassUnknown   Class = ""
	ClassPrivateIP Class = "PrivateIP"
	ClassWAN       Class = "WAN"
)

type Input struct {
	CustomerName string
	Networks     []string
	MaxAddresses uint64
}

type Plan struct {
	CustomerName string
	CustomerKey  string
	Targets      []Target
}

type Analysis struct {
	Plan            Plan
	CanonicalInputs []CanonicalInput
	Diagnostics     []Diagnostic
	UniqueAddresses uint64
}

type CanonicalInput struct {
	Input  string
	Prefix netip.Prefix
	Class  Class
}

type Diagnostic struct {
	Kind    string
	Input   string
	Related string
	Message string
}

type Target struct {
	Class        Class
	Sequence     int
	Name         string
	TaskName     string
	Prefixes     []netip.Prefix
	AddressCount uint64
	Hash         string
}

func Build(input Input) (Plan, error) {
	name := strings.TrimSpace(input.CustomerName)
	if name == "" {
		return Plan{}, errors.New("networkplan: customer name is required")
	}

	maxAddresses := input.MaxAddresses
	if maxAddresses == 0 {
		maxAddresses = DefaultMaxAddresses
	}
	if maxAddresses > DefaultMaxAddresses {
		return Plan{}, fmt.Errorf(
			"networkplan: maximum addresses %d exceeds greenbone limit %d",
			maxAddresses,
			DefaultMaxAddresses,
		)
	}

	prefixes, err := parseAndExpand(input.Networks)
	if err != nil {
		return Plan{}, err
	}
	prefixes = removeOverlaps(prefixes)

	byClass := map[Class][]netip.Prefix{
		ClassPrivateIP: {},
		ClassWAN:       {},
	}
	for _, prefix := range prefixes {
		class, classifyErr := classify(prefix)
		if classifyErr != nil {
			return Plan{}, classifyErr
		}
		byClass[class] = append(byClass[class], prefix)
	}

	key := SafeName(name)
	targets := make([]Target, 0)
	for _, class := range []Class{ClassPrivateIP, ClassWAN} {
		classTargets := pack(key, class, byClass[class], maxAddresses)
		targets = append(targets, classTargets...)
	}
	if len(targets) > maxTargetsPerPlan {
		return Plan{}, fmt.Errorf(
			"networkplan: target count %d exceeds safety limit %d",
			len(targets),
			maxTargetsPerPlan,
		)
	}

	return Plan{
		CustomerName: name,
		CustomerKey:  key,
		Targets:      targets,
	}, nil
}

func Analyze(input Input) (Analysis, error) {
	plan, err := Build(input)
	if err != nil {
		return Analysis{}, err
	}
	canonical := make([]CanonicalInput, 0, len(input.Networks))
	diagnostics := make([]Diagnostic, 0)
	seen := make(map[netip.Prefix]string, len(input.Networks))
	for _, raw := range input.Networks {
		prefix, err := Parse(raw)
		if err != nil {
			return Analysis{}, err
		}
		class, err := classify(prefix)
		if err != nil {
			return Analysis{}, err
		}
		if related, duplicate := seen[prefix]; duplicate {
			diagnostics = append(diagnostics, Diagnostic{
				Kind:    "duplicate",
				Input:   raw,
				Related: related,
				Message: fmt.Sprintf("%s duplicates %s and will be scanned once", raw, related),
			})
			continue
		}
		for _, existing := range canonical {
			if prefixesOverlap(prefix, existing.Prefix) {
				diagnostics = append(diagnostics, Diagnostic{
					Kind:    "overlap",
					Input:   raw,
					Related: existing.Input,
					Message: fmt.Sprintf("%s overlaps %s; covered addresses will be scanned once", raw, existing.Input),
				})
			}
		}
		seen[prefix] = raw
		canonical = append(canonical, CanonicalInput{Input: raw, Prefix: prefix, Class: class})
	}
	var total uint64
	for _, target := range plan.Targets {
		total += target.AddressCount
	}
	return Analysis{
		Plan:            plan,
		CanonicalInputs: canonical,
		Diagnostics:     diagnostics,
		UniqueAddresses: total,
	}, nil
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func Parse(input string) (netip.Prefix, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return netip.Prefix{}, errors.New("networkplan: network is empty")
	}
	if !strings.Contains(raw, "/") {
		raw += "/32"
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("networkplan: parsing network %q: %w", input, err)
	}
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("networkplan: network %q is not ipv4", input)
	}
	return prefix.Masked(), nil
}

func SafeName(name string) string {
	var builder strings.Builder
	lastSeparator := false
	for _, char := range strings.TrimSpace(name) {
		isAllowed := unicode.IsLetter(char) || unicode.IsDigit(char) || char == '-'
		if isAllowed && char <= unicode.MaxASCII {
			builder.WriteRune(char)
			lastSeparator = false
			continue
		}
		if !lastSeparator && builder.Len() > 0 {
			builder.WriteByte('_')
			lastSeparator = true
		}
	}
	result := strings.Trim(builder.String(), "_")
	if result == "" {
		result = "Customer"
	}
	if len(result) > 64 {
		result = strings.TrimRight(result[:64], "_")
	}
	return result
}

func parseAndExpand(inputs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(inputs))
	for _, input := range inputs {
		prefix, err := Parse(input)
		if err != nil {
			return nil, err
		}
		expanded, err := split(prefix)
		if err != nil {
			return nil, err
		}
		if len(prefixes)+len(expanded) > maxExpandedPrefixes {
			return nil, fmt.Errorf(
				"networkplan: expanded network count exceeds safety limit %d",
				maxExpandedPrefixes,
			)
		}
		prefixes = append(prefixes, expanded...)
	}
	return prefixes, nil
}

func split(prefix netip.Prefix) ([]netip.Prefix, error) {
	if prefix.Bits() >= 24 {
		return []netip.Prefix{prefix}, nil
	}
	count := 1 << (24 - prefix.Bits())
	if count > maxExpandedPrefixes {
		return nil, fmt.Errorf(
			"networkplan: network %s expands to %d /24 prefixes, limit is %d",
			prefix,
			count,
			maxExpandedPrefixes,
		)
	}

	base := ipv4Number(prefix.Addr())
	result := make([]netip.Prefix, 0, count)
	for index := range count {
		address := ipv4Address(base + uint32(index)*256)
		result = append(result, netip.PrefixFrom(address, 24))
	}
	return result, nil
}

func removeOverlaps(prefixes []netip.Prefix) []netip.Prefix {
	slices.SortFunc(prefixes, func(left, right netip.Prefix) int {
		if compared := left.Addr().Compare(right.Addr()); compared != 0 {
			return compared
		}
		return left.Bits() - right.Bits()
	})

	result := make([]netip.Prefix, 0, len(prefixes))
	var coveredThrough uint64
	hasCoverage := false
	for _, prefix := range prefixes {
		start := uint64(ipv4Number(prefix.Addr()))
		end := start + addressCount(prefix) - 1
		if hasCoverage && start <= coveredThrough {
			continue
		}
		result = append(result, prefix)
		coveredThrough = end
		hasCoverage = true
	}
	return result
}

func classify(prefix netip.Prefix) (Class, error) {
	first := prefix.Addr()
	last := prefixLastAddress(prefix)
	if first.IsPrivate() && last.IsPrivate() {
		return ClassPrivateIP, nil
	}
	if !first.IsGlobalUnicast() || !last.IsGlobalUnicast() || isSpecial(first) || isSpecial(last) {
		return ClassUnknown, fmt.Errorf("networkplan: network %s is special-use and cannot be scanned", prefix)
	}
	return ClassWAN, nil
}

func prefixLastAddress(prefix netip.Prefix) netip.Addr {
	start := uint64(ipv4Number(prefix.Addr()))
	end := start + addressCount(prefix) - 1
	if end > uint64(^uint32(0)) {
		panic("networkplan: ipv4 prefix exceeds address space")
	}
	return ipv4Address(uint32(end))
}

var specialPrefixes = mustPrefixes(
	"0.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
)

func isSpecial(address netip.Addr) bool {
	for _, prefix := range specialPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func mustPrefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}

func pack(customerKey string, class Class, prefixes []netip.Prefix, limit uint64) []Target {
	result := make([]Target, 0)
	current := make([]netip.Prefix, 0)
	var currentCount uint64

	flush := func() {
		if len(current) == 0 {
			return
		}
		sequence := len(result) + 1
		prefixCopy := slices.Clone(current)
		result = append(result, Target{
			Class:        class,
			Sequence:     sequence,
			Name:         fmt.Sprintf("%s_%s_Target%d", customerKey, class, sequence),
			TaskName:     fmt.Sprintf("%s_%s_Task%d", customerKey, class, sequence),
			Prefixes:     prefixCopy,
			AddressCount: currentCount,
			Hash:         targetHash(class, prefixCopy),
		})
		current = make([]netip.Prefix, 0)
		currentCount = 0
	}

	for _, prefix := range prefixes {
		count := addressCount(prefix)
		if currentCount > 0 && currentCount+count > limit {
			flush()
		}
		current = append(current, prefix)
		currentCount += count
	}
	flush()
	return result
}

func addressCount(prefix netip.Prefix) uint64 {
	return uint64(1) << (32 - prefix.Bits())
}

func targetHash(class Class, prefixes []netip.Prefix) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(class))
	for _, prefix := range prefixes {
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(prefix.String()))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func ipv4Number(address netip.Addr) uint32 {
	bytes := address.As4()
	return binary.BigEndian.Uint32(bytes[:])
}

func ipv4Address(value uint32) netip.Addr {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], value)
	return netip.AddrFrom4(bytes)
}
