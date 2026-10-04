package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// RIS whois dumps of the combined RIS routing tables.
// Format: <origin> <tab> <prefix> <tab> <seen by #rispeers>
var risDumpURLs = []string{
	"https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz",
	"https://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz",
}

const (
	fetchAttempts = 3
	// minPeersSeeing drops routes seen by few RIS peers,
	// which are mostly leaks, hijacks and local defaults.
	minPeersSeeing = 10
)

// fetchAnnouncedPrefixes returns the prefixes announced by every origin AS.
func fetchAnnouncedPrefixes(ctx context.Context, client *http.Client) (map[uint32][]netip.Prefix, error) {
	announced := make(map[uint32][]netip.Prefix)
	for _, url := range risDumpURLs {
		routes, err := fetchWithRetry(ctx, client, url)
		if err != nil {
			return nil, err
		}
		for _, route := range routes {
			for _, asn := range route.Origins {
				announced[asn] = append(announced[asn], route.Prefix)
			}
		}
	}
	return announced, nil
}

func fetchWithRetry(ctx context.Context, client *http.Client, url string) ([]route, error) {
	const attemptDuration = 5 * time.Second
	var err error
	for attempt := range fetchAttempts {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * attemptDuration):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		var routes []route
		routes, err = fetchDump(ctx, client, url)
		if err == nil {
			return routes, nil
		}
	}
	return nil, E.Cause(err, "fetch ", url)
}

func fetchDump(ctx context.Context, client *http.Client, url string) ([]route, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, E.New("unexpected status: ", response.Status)
	}
	reader, err := gzip.NewReader(response.Body)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return parseDump(reader)
}

type route struct {
	Origins []uint32
	Prefix  netip.Prefix
}

// parseDump parses a RIS whois dump, skipping comments,
// default routes and routes seen by fewer than minPeersSeeing peers.
func parseDump(reader io.Reader) ([]route, error) {
	var routes []route
	scanner := bufio.NewScanner(reader)
	for line := 1; scanner.Scan(); line++ {
		text := scanner.Text()
		if text == "" || strings.HasPrefix(text, "%") {
			continue
		}
		parsed, ok, err := parseRoute(text)
		if err != nil {
			return nil, E.Cause(err, "parse at line ", line)
		}
		if ok {
			routes = append(routes, parsed)
		}
	}
	err := scanner.Err()
	if err != nil {
		return nil, err
	}
	return routes, nil
}

func parseRoute(text string) (route route, ok bool, err error) {
	fields := strings.Split(text, "\t")
	if len(fields) != 3 {
		return route, false, E.New("invalid line: ", text)
	}
	seen, err := strconv.Atoi(fields[2])
	if err != nil {
		return route, false, err
	}
	prefix, err := netip.ParsePrefix(fields[1])
	if err != nil {
		return route, false, err
	}
	if seen < minPeersSeeing || prefix.Bits() == 0 {
		return route, false, nil
	}
	route.Prefix = prefix.Masked()
	// Multi-origin prefixes are written as an AS set: {a,b}
	origins := strings.Split(strings.Trim(fields[0], "{}"), ",")
	route.Origins = make([]uint32, 0, len(origins))
	for _, origin := range origins {
		asn, err := strconv.ParseUint(origin, 10, 32)
		if err != nil {
			return route, false, E.Cause(err, "parse origin ", fields[0])
		}
		route.Origins = append(route.Origins, uint32(asn))
	}
	return route, true, nil
}
