# tracelet-policy-library

Curated, versioned policy packs for [Tracelet](https://tracelet.io). Each pack is a collection of governance rules for a specific domain (Kubernetes, Docker, AWS, Git, etc.) that can be installed into any Tracelet organisation in one click from the **Governance → Policy → Packs** page.

---

## How packs are consumed

The Tracelet API is pointed at this repo via the `POLICY_PACKS_REPO_URL` environment variable (set to the raw base URL of this repo, e.g. `https://raw.githubusercontent.com/insighture/tracelet-policy-library/main`).

| Operation | URL fetched |
|-----------|-------------|
| List catalogue | `${POLICY_PACKS_REPO_URL}/index.json` |
| Load a pack | `${POLICY_PACKS_REPO_URL}/packs/{id}.json` |

Installing a pack creates one **pre-approved, enabled policy group** in the organisation, containing all the pack's rules as child tool policies. The group is immediately active and distributed to agents. Re-installing a pack that is already installed is a no-op (the API returns 409 Conflict).

---

## Repository layout

```
index.json          ← catalogue (metadata only; fetched to build the UI grid)
packs/
  {id}.json         ← one file per pack (full rules; fetched on detail/install)
```

---

## Pack file schema

```jsonc
{
  "id": "kubernetes-baseline",          // kebab-case; matches filename stem
  "name": "Kubernetes Baseline",        // human display name
  "category": "kubernetes",             // one of: kubernetes, docker, aws, git,
                                        //         secrets, database, terraform, filesystem
  "description": "...",
  "version": "1.0.0",                   // semver; bump on any rule change
  "rules": [ /* see Rule schema below */ ]
}
```

### Rule schema

```jsonc
{
  "name": "Block kubectl delete namespace",   // required; human display name
  "description": "...",                        // required; explain why
  "action": "block",                           // see Action values below
  "fail_mode": "closed",                       // "closed" | "open"
  "severity": "critical",                      // "critical" | "high" | "medium" | "low"
  "priority": 100,                             // integer; lower = higher priority = evaluated first
  "rule_type": "command_filter",               // see Rule types below
  "rule_config": { ... },                      // inline object; schema depends on rule_type
  "events": ["pre_tool_use"],                  // array of event kinds; [] or omit = all events
  "tools": ["Bash"]                            // array of tool names; null or omit = all tools
}
```

---

## Action values

| Action | Effect |
|--------|--------|
| `block` | Hard deny — execution is stopped immediately. |
| `justify` | Require the developer to provide a written reason. Execution proceeds once the reason is supplied. |
| `request_access` | Require an admin to grant a one-time approval. Execution is held until the grant arrives. |
| `approve` | Require an explicit human confirmation before proceeding. |
| `redact` | Mask matched fields (secrets, PII) in the event, then allow execution with the sanitised data. |
| `warn` | Record a warning finding and allow execution. Does not block. |
| `log` | Record the event silently. Does not block or warn. |

**`allow` is not an authorable action.** The implicit verdict when no policy fires is allow. To express "allow this subset of commands", use `allowed_commands` / `allowed_patterns` inside a `command_filter` rule config.

---

## fail_mode

| Value | Meaning |
|-------|---------|
| `closed` | Fail-safe: if policy evaluation errors, the rule fires anyway (conservative). Use for deterministic pattern-based blocks. |
| `open` | Fail-open: if evaluation errors, the rule does not fire. Use for detection-based rules (secret scanning, PII detection) where false positives on engine failure are more costly than a miss. |

---

## Rule types

### `command_filter`
Matches against the shell command text (case-insensitive for `blocked_commands`; RE2 regex for `blocked_patterns`). At least one field must be non-empty.

```json
{
  "blocked_commands": ["rm -rf /"],
  "blocked_patterns": ["kubectl\\s+delete\\s+(ns|namespace)\\b"],
  "allowed_commands": ["kubectl get"],
  "allowed_patterns": ["kubectl\\s+get.*"]
}
```

- `blocked_commands` — case-insensitive substring match → trigger.
- `blocked_patterns` — Go RE2 regex → trigger. Matched against original AND lowercased command.
- `allowed_commands` — case-insensitive substring → explicit allow (overrides block).
- `allowed_patterns` — RE2 regex → explicit allow.

### `file_access`
Matches against the file path. Supports `**` globbing, `~`, and `$PROJECT_DIR` (substituted with the event's working directory).

```json
{
  "blocked_paths": ["/etc/shadow", "**/.env"],
  "allowed_paths": ["$PROJECT_DIR/**", "/tmp/**"]
}
```

If `allowed_paths` is non-empty, any access to a path not matching an allowed pattern will trigger the rule.

### `secret_detection`
Scans event text (prompt, command, tool input, tool output) for credentials using the embedded gitleaks ruleset (~195 rules) plus optional custom RE2 regexes.

```json
{
  "use_builtins": true,
  "patterns": ["myco_[a-zA-Z0-9]{32}"],
  "allowlist": ["example-key"],
  "disabled_builtins": ["generic-api-key"]
}
```

- `use_builtins` — bool — enable the built-in gitleaks ruleset (default `true`).
- `patterns` — string[] — extra RE2 regexes; capture group 1 (if present) is the secret value.
- `allowlist` — string[] — case-insensitive suppress substrings.
- `enabled_builtins` / `disabled_builtins` — string[] — allowlist/denylist by gitleaks rule ID.

### `content_filter`
Matches RE2 regex patterns against the full prompt or tool-call text. `blocked_patterns` is **required**.

```json
{
  "blocked_patterns": ["(akia|asia|aroa)[0-9a-z]{16}"]
}
```

### `pii_redact`
Redacts PII categories from event text. Works with `redact` action.

```json
{
  "redaction_categories": ["EMAIL", "PHONE", "CREDIT_CARD"],
  "notify_user": true
}
```

Valid categories: `EMAIL`, `SSN`, `CREDIT_CARD`, `PHONE`, `IP_ADDRESS`, `DATE_OF_BIRTH`, `PASSPORT`, `IBAN`, `NAME`, `ADDRESS`.

### `mcp_filter`
Controls which MCP servers and tools may be called, and what arguments they may receive.

```json
{
  "server_permissions": {
    "github": {
      "allowed_tools": ["create_issue", "get_*"],
      "blocked_tools": ["delete_repo"]
    }
  },
  "allowed_servers": ["github", "filesystem"],
  "blocked_tools": ["mcp__*__delete*"],
  "blocked_arguments": ["password|secret|token"],
  "blocked_paths": ["/etc/shadow"],
  "allowed_paths": ["/src/**"]
}
```

- `server_permissions` — per-server allow/block lists (supports globs, e.g. `get_*`).
- `blocked_tools` — global glob vs full MCP tool name (`mcp__server__tool`).
- `blocked_arguments` — RE2 regex vs the JSON-marshalled MCP tool input.

### `opa`
Full Rego policy for advanced use cases. `rego` and `query` are required.

```json
{
  "rego": "package tracelet.agent\nmatch if { ... }",
  "query": "data.tracelet.agent.match"
}
```

---

## Event kinds

| Kind | When it fires |
|------|---------------|
| `user_prompt` | When the developer submits a prompt to the AI. |
| `pre_tool_use` | Before the AI executes a tool call (Bash, Write, MCP, etc.). |
| `post_tool_use` | After a tool call completes successfully. |
| `post_tool_use_failure` | After a tool call fails. |

An empty `events` array (or omitting the field) means the rule fires on all event kinds.

---

## Priority

Rules within a policy group are evaluated in ascending priority order (lower number = evaluated first). `block` short-circuits immediately — once a block fires, no further rules are evaluated for that event. Use lower priority numbers for the most critical, high-confidence blocks, and higher numbers for softer actions (justify, warn).

---

## Adding a new pack

1. Create `packs/{id}.json` following the schema above.
2. Add an entry to `index.json` with the correct `rule_count` matching the number of items in `rules`.
3. Bump `version` in both files for any rule changes.
4. Validate JSON: `python3 -m json.tool packs/{id}.json > /dev/null`.
5. Verify all regex patterns are RE2-valid (no lookaheads, no backreferences).

## Derived packs (dcg import)

The `*-guard` and `*-extended` packs are derived from the pattern library of
[destructive_command_guard](https://github.com/Dicklesworthstone/destructive_command_guard)
(© Jeffrey Emanuel, used under its license terms), converted to this
library's schema and Go RE2 regex syntax. When editing them, bump the pack
version in both the pack file and `index.json`.

---

## Category set

`kubernetes` · `docker` · `aws` · `git` · `secrets` · `database` · `terraform` · `filesystem` · `gcp` · `azure` · `cicd` · `messaging` · `search` · `backup` · `dns` · `cdn` · `monitoring` · `payment` · `platform` · `email` · `featureflags` · `loadbalancer` · `apigateway` · `infrastructure` · `packages` · `remote` · `system`

The dashboard's category filter and icon maps (`governance.policy.tool-policies.tsx` in the tracelet repo) must list every category used here.
