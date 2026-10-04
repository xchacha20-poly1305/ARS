package main

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/provider"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
)

var testPrefixes = []netip.Prefix{
	netip.MustParsePrefix("1.1.1.0/24"),
	netip.MustParsePrefix("104.16.0.0/13"),
	netip.MustParsePrefix("2606:4700::/32"),
}

func TestWriteSRS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.srs")
	err := writeSRS(path, testPrefixes)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ruleSet, err := srs.Read(file, true)
	if err != nil {
		t.Fatal(err)
	}
	if ruleSet.Version != C.RuleSetVersion1 {
		t.Fatalf("version = %d, want %d", ruleSet.Version, C.RuleSetVersion1)
	}
	rules := ruleSet.Options.Rules
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	got := []string(rules[0].DefaultOptions.IPCIDR)
	if !slices.Equal(got, prefixStrings(testPrefixes)) {
		t.Fatalf("ip_cidr = %v", got)
	}
}

func TestWriteMRS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.mrs")
	err := writeMRS(path, testPrefixes)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var dump bytes.Buffer
	err = provider.ConvertToMrs(content, P.IPCIDR, P.MrsRule, &dump)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(dump.String())
	if !slices.Equal(got, prefixStrings(testPrefixes)) {
		t.Fatalf("prefixes = %v", got)
	}
}

func TestMergePrefixes(t *testing.T) {
	input := append(slices.Clone(testPrefixes),
		netip.MustParsePrefix("1.1.1.128/25"),
		netip.MustParsePrefix("2606:4700:1::/48"),
	)
	got, err := mergePrefixes(input)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, testPrefixes) {
		t.Fatalf("prefixes = %v", got)
	}
}

func TestParseDump(t *testing.T) {
	dump := "% comment\n" +
		"\n" +
		"174\t0.0.0.0/0\t40\n" +
		"13335\t1.1.1.0/24\t300\n" +
		"{8035,13979}\t15.0.64.0/18\t313\n" +
		"64512\t10.0.0.0/8\t3\n"
	routes, err := parseDump(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	want := []route{
		{Origins: []uint32{13335}, Prefix: netip.MustParsePrefix("1.1.1.0/24")},
		{Origins: []uint32{8035, 13979}, Prefix: netip.MustParsePrefix("15.0.64.0/18")},
	}
	if !slices.EqualFunc(routes, want, func(a, b route) bool {
		return a.Prefix == b.Prefix && slices.Equal(a.Origins, b.Origins)
	}) {
		t.Fatalf("routes = %v", routes)
	}
}

func prefixStrings(prefixes []netip.Prefix) []string {
	result := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		result[i] = prefix.String()
	}
	return result
}
