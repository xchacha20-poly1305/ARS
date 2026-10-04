# ARS

AS (Autonomous System) Rule Set

ARS reads the full routing tables collected by [RIPE RIS](https://www.ris.ripe.net/dumps/) (`riswhoisdump.IPv4.gz` and `riswhoisdump.IPv6.gz`), and for every origin AS generates a rule set of the prefixes it announces:

- sing-box binary rule sets `.srs` (version 1, `ip_cidr` rule)
- mihomo binary rule sets `.mrs` (`ipcidr` behavior)

## Download

Each AS has its own file named `AS<number>`, for example `AS13335.srs` and `AS13335.mrs`.

- `srs` branch: all `.srs` files
- `mrs` branch: all `.mrs` files
- [Releases](../../releases): `srs.zip` and `mrs.zip`; the latest 10 releases are kept

sing-box:

```json
{
  "tag": "AS13335",
  "type": "remote",
  "format": "binary",
  "url": "https://raw.githubusercontent.com/xchacha20-poly1305/ARS/srs/AS13335.srs"
}
```

mihomo:

```yaml
rule-providers:
  AS13335:
    type: http
    behavior: ipcidr
    format: mrs
    url: https://raw.githubusercontent.com/xchacha20-poly1305/ARS/mrs/AS13335.mrs
```

## Data

- Routes seen by fewer than 10 RIS peers and default routes are dropped.
- A prefix announced by multiple origins (an AS set such as `{8035,13979}`) is included in the rule set of each of them.
- The prefixes of each AS are merged before writing.

## Run locally

```sh
go run . -o output
```

The output is written to `output/srs/` and `output/mrs/`.

## Automated release

`.github/workflows/release.yml` runs daily, on push to `main`, and on manual dispatch. It generates the rule sets, force-pushes them to the `srs` and `mrs` branches, publishes a release with `gh release create`, and deletes releases beyond the latest 10 with `gh release delete`.

# LICENSE

[GPL-3.0-or-later](./LICENSE)