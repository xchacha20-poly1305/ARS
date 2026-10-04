package main

import (
	"context"
	"flag"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"time"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"

	"go4.org/netipx"
)

func main() {
	outputDir := flag.String("o", "output", "output directory")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	err := run(ctx, *outputDir)
	if err != nil {
		log.FatalContext(ctx, err)
	}
}

func run(ctx context.Context, outputDir string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	announced, err := fetchAnnouncedPrefixes(ctx, client)
	if err != nil {
		return err
	}

	err = prepareOutputDir(outputDir)
	if err != nil {
		return err
	}
	for _, asn := range slices.Sorted(maps.Keys(announced)) {
		name := F.ToString("AS", asn)
		prefixes, err := mergePrefixes(announced[asn])
		if err != nil {
			return E.Cause(err, name)
		}
		err = writeRuleSet(outputDir, name, prefixes)
		if err != nil {
			return E.Cause(err, name)
		}
	}
	log.InfoContext(ctx, len(announced), " rule sets written")
	return nil
}

// mergePrefixes returns the merged, sorted prefixes.
func mergePrefixes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	var builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		builder.AddPrefix(prefix)
	}
	set, err := builder.IPSet()
	if err != nil {
		return nil, err
	}
	return set.Prefixes(), nil
}
