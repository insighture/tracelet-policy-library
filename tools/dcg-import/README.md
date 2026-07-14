# dcg-import

Imports the pattern library of [destructive_command_guard](https://github.com/Dicklesworthstone/destructive_command_guard)
(dcg) into tracelet policy packs. dcg embeds ~850 destructive-command regexes
in Rust macro invocations; this tooling extracts them, converts them to Go
RE2, and emits packs in this library's schema.

## Pipeline

```bash
# 1. Extract the rule data out of the dcg Rust sources
python tools/dcg-import/extract.py <path-to-dcg-checkout> tools/dcg-import/corpus.json

# 2. Generate the packs (writes packs/*.json and updates index.json)
python tools/dcg-import/generate.py tools/dcg-import/corpus.json .

# 3. Validate everything (schema + RE2 compile + index consistency)
go run ./tools/validate-packs .
go test ./tools/validate-packs/
```

Wave 1 (`WAVE1` in `generate.py`) covers the categories the dashboard already
knew: database, aws, kubernetes, docker, git, secrets, terraform, filesystem.
Wave 2 (`WAVE2`) adds gcp, azure, cicd, messaging, search, backup, dns, cdn,
monitoring, payment, platform, email, featureflags, loadbalancer, apigateway,
infrastructure, packages, remote, and system — these categories must be
listed in the dashboard's category filter/icon maps
(`governance.policy.tool-policies.tsx`).

## Field mapping

| dcg | tracelet |
|---|---|
| pattern regex | `rule_config.blocked_patterns` (one rule per pattern) |
| severity `critical/high/medium/low` | `severity` (identical) |
| severity `critical` | `action: request_access`, `fail_mode: closed`, priority 100+ |
| severity `high` | `action: justify`, `fail_mode: closed`, priority 200+ |
| severity `medium` | `action: warn`, `fail_mode: open`, priority 300+ |
| severity `low` | `action: log`, `fail_mode: open`, priority 400+ |
| reason + first suggestion | rule `description` |
| pack-level safe patterns | `allowed_patterns` on every rule of that pack |

## Regex conversion (Rust regex/fancy_regex → Go RE2)

~85% of dcg patterns are RE2-clean and port verbatim. The rest use
lookarounds, handled as follows (see `generate.py` for the mechanisms):

- `(?<name>` → `(?P<name>` (mechanical).
- A positive lookahead spanning to the end of the pattern → consuming group
  (mechanical; nothing follows it).
- dcg's `..`-path-traversal guards on /tmp safelists → a positive
  "no two consecutive dots" form. Strictly narrower, so the conversion can
  only prompt more, never exempt more.
- Negative lookaheads that exempt safe variants (`--dry-run`, `fdisk -l`,
  `checkout -b`, `restore --staged`, `-WhatIf`) → moved to per-rule
  `allowed_patterns`, tracelet's native mechanism for exactly that.
- `CONVERT_LOOKAHEADS`: patterns whose lookaheads are pure boundary
  assertions verified safe to convert to consuming groups wholesale.
- `REGEX_OVERRIDES`: full hand-written RE2 replacements for the remainder.

Anything not covered is reported and skipped, never emitted broken.

## Compound-command hardening

The tracelet agent matches rules against the whole command string, so an
allow that matches one segment of `safe-thing && destructive-thing` must not
exempt the destructive segment:

- Pack-level safelists are attached only when start-anchored (`^...`); the
  valuable ones (`rm -rf /tmp/...`) are fully `^...$`-anchored in dcg.
- Per-rule allows carry a `[^;&]*$` tail: nothing may follow the exempting
  flag except pipe segments.

`tools/validate-packs/behavior_test.go` contains explicit bypass-attempt
cases; run `go test ./tools/validate-packs/` after any regeneration.

## Attribution

The imported patterns and descriptions are derived from
destructive_command_guard, © Jeffrey Emanuel, used under its license terms.
