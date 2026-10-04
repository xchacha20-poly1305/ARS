package main

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"

	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/provider"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

type Format struct {
	Name  string
	Write func(path string, prefixes []netip.Prefix) error
}

var formats = []Format{
	{Name: "srs", Write: writeSRS},
	{Name: "mrs", Write: writeMRS},
}

func writeSRS(path string, prefixes []netip.Prefix) error {
	cidrs := common.Map(prefixes, func(it netip.Prefix) string {
		return it.String()
	})
	ruleSet := option.PlainRuleSet{
		Rules: []option.HeadlessRule{{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultHeadlessRule{
				IPCIDR: cidrs,
			},
		}},
	}
	var buffer bytes.Buffer
	// Use version 1 for compatible
	err := srs.Write(&buffer, ruleSet, C.RuleSetVersion1)
	if err != nil {
		return err
	}
	return os.WriteFile(path, buffer.Bytes(), 0o644)
}

func writeMRS(path string, prefixes []netip.Prefix) error {
	var text bytes.Buffer
	for _, prefix := range prefixes {
		text.WriteString(prefix.String())
		text.WriteByte('\n')
	}
	var buffer bytes.Buffer
	err := provider.ConvertToMrs(text.Bytes(), P.IPCIDR, P.TextRule, &buffer)
	if err != nil {
		return err
	}
	return os.WriteFile(path, buffer.Bytes(), 0o644)
}

func writeRuleSet(outputDir, name string, prefixes []netip.Prefix) error {
	for _, format := range formats {
		path := filepath.Join(outputDir, format.Name, name+"."+format.Name)
		err := format.Write(path, prefixes)
		if err != nil {
			return E.Cause(err, "write format ", format.Name, " at ", path)
		}
	}
	return nil
}

func prepareOutputDir(outputDir string) error {
	for _, format := range formats {
		dir := filepath.Join(outputDir, format.Name)
		err := os.RemoveAll(dir)
		if err != nil {
			return err
		}
		err = os.MkdirAll(dir, 0o755)
		if err != nil {
			return err
		}
	}
	return nil
}
