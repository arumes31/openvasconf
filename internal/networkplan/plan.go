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
	intervals := make([]analysisInterval, 0, len(input.Networks))
	diagnostics := make([]Diagnostic, 0)
	seen := make(map[netip.Prefix]string, len(input.Networks))
	for _, raw := range input.Networks {
		expanded, err := Expand(raw)
		if err != nil {
			return Analysis{}, err
		}
		for _, prefix := range expanded {
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
			seen[prefix] = raw
			canonicalInput := CanonicalInput{Input: raw, Prefix: prefix, Class: class}
			canonical = append(canonical, canonicalInput)
			start := uint64(ipv4Number(prefix.Addr()))
			intervals = append(intervals, analysisInterval{
				CanonicalInput: canonicalInput,
				Start:          start,
				End:            start + addressCount(prefix) - 1,
			})
		}
	}
	slices.SortStableFunc(intervals, func(left, right analysisInterval) int {
		switch {
		case left.Start < right.Start:
			return -1
		case left.Start > right.Start:
			return 1
		case left.End > right.End:
			return -1
		case left.End < right.End:
			return 1
		default:
			return 0
		}
	})
	if len(intervals) > 0 {
		covered := intervals[0]
		for _, current := range intervals[1:] {
			if current.Start <= covered.End {
				diagnostics = append(diagnostics, Diagnostic{
					Kind:    "overlap",
					Input:   current.Input,
					Related: covered.Input,
					Message: fmt.Sprintf(
						"%s overlaps %s; covered addresses will be scanned once",
						current.Input,
						covered.Input,
					),
				})
			}
			if current.End > covered.End {
				covered = current
			}
		}
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

type analysisInterval struct {
	CanonicalInput
	Start uint64
	End   uint64
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

// Expand parses a single network input into its canonical set of CIDR
// prefixes. Besides plain addresses and CIDRs it accepts an inclusive IPv4
// range written as "start-end" and converts it into the smallest exact set
// of CIDRs.
func Expand(input string) ([]netip.Prefix, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return nil, errors.New("networkplan: network is empty")
	}
	if strings.Contains(raw, "-") {
		return parseRange(raw)
	}
	prefix, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return []netip.Prefix{prefix}, nil
}

func parseRange(raw string) ([]netip.Prefix, error) {
	parts := strings.Split(raw, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("networkplan: invalid range %q", raw)
	}
	start, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("networkplan: parsing range start %q: %w", raw, err)
	}
	end, err := netip.ParseAddr(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("networkplan: parsing range end %q: %w", raw, err)
	}
	if !start.Is4() || !end.Is4() {
		return nil, fmt.Errorf("networkplan: range %q is not ipv4", raw)
	}
	startNumber := uint64(ipv4Number(start))
	endNumber := uint64(ipv4Number(end))
	if startNumber > endNumber {
		return nil, fmt.Errorf("networkplan: range %q starts after its end", raw)
	}

	prefixes := make([]netip.Prefix, 0, 8)
	for startNumber <= endNumber {
		remaining := endNumber - startNumber + 1
		block := uint64(1)
		// Grow the block while it stays aligned and within the range.
		for block<<1 <= remaining && startNumber%(block<<1) == 0 && block < 1<<32 {
			block <<= 1
		}
		bits := 32
		for size := block; size > 1; size >>= 1 {
			bits--
		}
		prefixes = append(prefixes, netip.PrefixFrom(ipv4Address64(startNumber), bits))
		if block == 1<<32 {
			break
		}
		startNumber += block
	}
	return prefixes, nil
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
		expanded, err := Expand(input)
		if err != nil {
			return nil, err
		}
		for _, prefix := range expanded {
			splitted, err := split(prefix)
			if err != nil {
				return nil, err
			}
			if len(prefixes)+len(splitted) > maxExpandedPrefixes {
				return nil, fmt.Errorf(
					"networkplan: expanded network count exceeds safety limit %d",
					maxExpandedPrefixes,
				)
			}
			prefixes = append(prefixes, splitted...)
		}
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

func ipv4Address64(value uint64) netip.Addr {
	if value > uint64(^uint32(0)) {
		panic("networkplan: ipv4 address exceeds address space")
	}
	var bytes [8]byte
	binary.BigEndian.PutUint64(bytes[:], value)
	return netip.AddrFrom4([4]byte(bytes[4:]))
}
