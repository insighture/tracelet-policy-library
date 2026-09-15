# Detection-pack parity gap analysis

Source: live walkthrough of a competitor's ("Speakeasy Gram") standard-policy
"Detect" step — 11 built-in detector categories, each expanded via its
"Customize" sub-panel to read the literal rule list (full taxonomy in
`speakeasy-detector-catalog-reference.md`). This doc records what's now
built, what was deliberately narrowed and why, and what still needs an
actual product/engineering decision rather than more pack-writing.

**Revision note:** the first pass of this doc shipped only 4 rules across
4 packs (one "confident" rule per category) and left the rest as "excluded,
too imprecise." That undersold what's actually achievable — this revision
covers every one of the 31 individually-named PII/Financial/Government/
Healthcare rules from the catalog (either as a working pack rule or as an
explicit, individually-reasoned exclusion), plus a full gitleaks-vs-catalog
diff for Secrets, plus a verified (compiled-and-evaluated, not just
hand-written) draft for Non-Corporate Accounts.

## Action-type convention (confirmed, not assumed)

Before writing any rule, every existing pack in this repo was checked for
its `action` usage: **zero of the 46 pre-existing packs use `"action":
"block"` anywhere.** The library's real convention is a three-tier
gradient by confidence/severity:

- `request_access` — critical/high severity, high-confidence match
  (irreversible operation, or a precise identifier format) → gate on admin
  approval.
- `justify` — medium severity, or a match with real false-positive
  potential (heuristic pattern, no independent context signal) → let the
  developer self-attest with a written reason and proceed, avoiding an
  admin-approval bottleneck on likely false positives.
- `warn` / `redact` — low severity or auto-sanitizable → log only, or mask
  and continue.

Every pack below follows this exact gradient. None use `block`.

---

## What's shipped now

| Pack | Category | Rules | Coverage |
|---|---|---|---|
| `pii-baseline.json` | `pii` | 2 | 4/4 named PII rules (2 combined into 1 redact rule + 1 justify rule) |
| `financial-baseline.json` | `financial` | 3 | 4/4 named Financial rules |
| `government-id-baseline.json` | `government` | 11 | **12/12** named Government ID rules — all countries, not just the US |
| `healthcare-id-baseline.json` | `healthcare` | 9 | **9/9** named Healthcare rules, at 3 explicit confidence tiers |
| `secrets-coverage-gap-guard.json` | `secrets` | 3 | 9 of ~25 confirmed gitleaks gaps (see §1) |
| `docs/drafts/non-corporate-accounts-baseline.draft.json` | — | 2 | Both Non-Corporate Accounts rules, verified-working Rego, **not installable yet** (see §5) |

That's every category from the catalog addressed except Off-Policy
Content, which the competitor's own product doesn't expose the rules for
(disabled/"coming soon" — nothing to build against).

---

## 1. Secrets: a real gitleaks-vs-catalog diff, not an assumption

The first pass of this doc claimed "detection parity already exists" for
Secrets without actually checking. This revision extracted all 195 rule
IDs from the real embedded ruleset (`agent/internal/policy/rules/gitleaks.toml`)
and diffed them against all 222 named rules in the catalog. Result: **~25
genuine gaps**, not zero. Full list, split by whether a safe regex could be
written:

**Shipped in `secrets-coverage-gap-guard.json` (9, high format-confidence):**
Anthropic API Key, Anthropic Admin API Key, Perplexity API Key, Notion API
Token (both `secret_...` and `ntn_...` formats), Airtable Personal Access
Token, 1Password Secret Key, Sourcegraph Access Token, Sonar API Token,
PKCS #12 File (file-extension check, not a content pattern). **The
Anthropic gap is the single most notable finding here** — this is an
AI-agent-governance product, and its own secret scanner had no rule for
its own primary AI provider's API keys.

**Deliberately NOT shipped (~16, too generic or no known public format):**
Amazon Bedrock API Key (Long/Short-Lived), Cisco Meraki API Key, Heroku API
Key (v2), Artifactory API Key, Artifactory Reference Token, ClickHouse
Cloud API Key, Looker Client ID, Looker Client Secret, Maxmind License Key,
Freemius Secret Key, SettleMint Application/Personal/Service Token (3),
Sentry Org Token, Sentry User Token. Each of these is either a bare
UUID/hex-string with no distinguishing prefix (Meraki, Heroku v2 — would
match almost anything), or has no publicly documented format I could find
with real confidence (Artifactory beyond what gitleaks already covers via
`jfrog-*`, ClickHouse, Looker, Maxmind, Freemius, SettleMint, Sentry's org/
user token variants). Shipping a guessed pattern for these would either
produce a flood of false positives or a false sense of coverage that isn't
real — worse than the honest gap.

**Ask:** if any specific one of the 16 becomes a real customer need, get
the actual current format from that provider's docs (not a guess) before
adding it.

---

## 2. Government Identifiers: all 12 shipped, none checksum-validated

Every one of the 12 named rules is now in `government-id-baseline.json`.
The 9 non-US ones are all format-only heuristics (`justify`, not
`redact`/`request_access`) because RE2 can compute neither modular-
arithmetic checksums (Spain NIF's mod-23 letter, Italy's check letter,
Singapore's weighted table, India Aadhaar's Verhoeff digit) nor lookahead-
based exclusion lists (the UK NINO's full HMRC-reserved-pair exclusion —
RE2 has no lookaround, so only the simpler excluded-letter-set constraint
is enforced, not the excluded-pair one). Every regex was tested against
real reference examples (valid CMS/HMRC/UIDAI/IT-government sample IDs
plus deliberately-invalid ones) before being committed — see the pack file
rule descriptions for what each one does and doesn't validate.

The bare-digit-run identifiers (UK NHS, UK passport, Australia TFN) only
fire when preceded by a matching keyword ("NHS number", "passport number",
"TFN") — without that anchor they'd match huge amounts of unrelated
numeric text.

**No further ask here** — this category is now complete relative to the
catalog. The only remaining judgment call is whether `justify` is the
right friction level for a given customer's risk tolerance, which is a
policy-authoring decision, not a pack-completeness one.

---

## 3. Healthcare: all 9 shipped, at 3 explicit confidence tiers

- **Tier 1 (`request_access`):** Medicare Beneficiary Identifier — CMS's
  format is tight enough (11 fixed positions, 6 excluded letters) to gate
  on admin approval with reasonable confidence.
- **Tier 2 (`justify`):** NPI (context-keyword + 10-digit shape; the real
  Luhn-style checksum against a fixed "80840" prefix can't be validated in
  RE2) and medical license number mentions (the competitor doesn't reveal
  its actual format, and there's no single US-wide standard — this rule is
  closer to a keyword flag than an identifier match).
- **Tier 3 (`warn` only):** the six semantic categories (disease/disorder
  mention, medication/drug name, treatment/procedure, clinical event,
  biological attribute, family history) — these are keyword/suffix
  heuristics standing in for what the competitor does with an NER model or
  LLM judge. They will both miss most real mentions and false-positive on
  non-clinical uses of the same words. This is a genuinely different
  capability tier from the rest of the pack, not just a lower-confidence
  regex — flagged clearly in both the pack description and every tier-3
  rule's own description so nobody mistakes `warn`-level coverage here for
  compliance-grade detection.

**Ask, if healthcare becomes a real target market:** NPI's checksum is a
small, well-defined function (Luhn variant against a fixed prefix) — worth
implementing as real validation code rather than staying a keyword
heuristic. The six semantic categories are a bigger, separate decision:
build/license an NER model, or route through the Intelligent Policy
Engine's LLM judge — don't build more keyword lists, they don't converge
toward NER-grade accuracy no matter how many terms you add.

---

## 4. Off-Policy Content — still nothing to build against

Unchanged from the first pass: the competitor's own product has this
disabled ("coming soon"), so there's no rule list to extract or build
against. Conceptually the closest match to Tracelet's Intelligent Policy
Engine, but exposed by the competitor as an **author-first**, per-org
policy (admin writes a plain-English rule, it's evaluated on every future
message) versus Tracelet's current **escalation-first** model (fires only
when no local Rego policy matches).

**Ask:** is `feat/policy-starter-evidence-grounding` already moving toward
letting an admin proactively author a semantic/LLM-judged rule via the
dashboard? If yes, this gap likely closes as a side effect of that work.

---

## 5. Non-Corporate Accounts — closer than the first pass claimed

The first pass of this doc said this "needs a new `rule_type`." That was
wrong, or at least imprecise — checked properly this time:

- **The data already exists.** `agent/internal/events/types.go`'s
  `EventRecord.ProviderAccountEmail` is populated on `KindSessionStart` for
  tools with a reliably-available local signal (captured by
  `agent/internal/sources/provideraccount`, issue #3112/#2744/#3132), and
  synced to Postgres (`events.provider_account_email`). This is **not** a
  store/ingest gap.
- **The `opa` rule_type doesn't need to be invented — it already exists**,
  and Rego can already reference `input.config` (the rule's `rule_config`,
  confirmed by reading `agent/internal/policy/opa/engine.go`'s
  `regoInput`), so an approved-domains allowlist is already expressible as
  policy-author-supplied config, not a schema change.
- **The actual, narrow gap:** `provider_account_email` is not yet added to
  the Rego input document. Two call sites build that input independently —
  `agent/internal/policy/opa/rule.go`'s `buildRegoInput` and
  `agent/internal/policy/opa/engine.go`'s `regoInput` — and per CLAUDE.md's
  "two orchestrators" pattern, both need the same one-line addition or one
  scenario silently keeps evaluating against an empty string.

`docs/drafts/non-corporate-accounts-baseline.draft.json` has both rules
fully written in Rego, **compiled and evaluated** (not just hand-written)
against 7 test cases (fires on personal-domain email, doesn't fire on
corporate domain, doesn't fire outside `session_start`, doesn't fire with
no email signal, empty-allowlist-never-fires, off-list-domain-fires,
on-list-domain-doesn't) — all passed. It's kept out of `packs/` and
`index.json` deliberately: until the one-line input-builder fix lands,
installing it would create a policy group that looks active in the
dashboard but never fires, which is worse than not having it.

**One extra thing this verification pass caught along the way:**
`agent/internal/policy/opa/rule.go` imports the pre-v1
`github.com/open-policy-agent/opa/rego` path, which parses Rego in v0 mode
(no mandatory `if` keyword) by default — confirmed by actually compiling
both syntax styles against it. Worth knowing if anyone on the team starts
authoring `opa` rules assuming modern Rego v1 syntax (with `if`/`:=`
required) — it will fail to compile against this specific code path, with
an error that doesn't obviously point at "wrong Rego dialect."

**Ask:** add `provider_account_email` (and probably `provider_account_plan`
too, for completeness) to both `buildRegoInput` and `regoInput`, then move
the draft pack into `packs/` + `index.json` as a real, installable pack.
This is now a small, well-scoped engine change, not a design project.

---

## 6. Dashboard-side follow-up (not yet applied — different repo/branch)

`dashboard/app/components/policy/policy-packs.tsx` needs `pii`, `financial`,
`government`, `healthcare` added to `PACKS_CATEGORY_OPTIONS` and
`PACK_CATEGORY_FALLBACK_ICON` (per this library's own README rule that
this file "must list every category used here"), plus a regression test
in `policy-packs.test.tsx` proving each resolves its own icon rather than
silently falling back to `BoxesIcon`. This was drafted once already in an
earlier pass of this work, but the dashboard repo has since moved to an
unrelated branch (`fix/policy-view-overrides-findings-4801`) and that draft
was not carried over. **Redo it as a small follow-up PR** against whichever
branch is current in `isee/dashboard` when these packs are ready to merge —
icon suggestions: `ShieldUserIcon` (pii), reuse `CreditCardIcon` (financial,
same icon as `payment` — fine, both are money-shaped), `IdentityCardIcon`
(government). No confirmed Hugeicons glyph checked yet for `healthcare` —
verify one exists before wiring it in.

Also not yet done anywhere: a UI equivalent of the competitor's per-rule
"Customize" panel (222 secrets rules browsable/toggleable across 12
subcategories with live counts). Now that §1 has confirmed there ARE real
gitleaks gaps, this is worth doing not just for browsing but as the natural
home for surfacing which specific rules are gitleaks-native vs. this
repo's own `secrets-coverage-gap-guard` additions.

Not yet done: a cross-cutting "detection sensitivity" confidence threshold
(competitor exposes a single 0–1 slider per policy). Worth considering for
any future confidence-scored Tracelet detector.

---

## Suggested sequencing

1. Ship the 5 real packs (`pii-baseline`, `financial-baseline`,
   `government-id-baseline`, `healthcare-id-baseline`,
   `secrets-coverage-gap-guard`) — no engine change, ready to review/merge
   from this worktree's branch (`feat/speakeasy-parity-detection-packs`)
   now.
2. Small, well-scoped: wire `provider_account_email` into both Rego input
   builders (§5), then promote the Non-Corporate Accounts draft into a real
   pack. This is the highest-value remaining item — it's not a design
   project anymore, just a small, verified change away from shipping.
3. Small: add `MAC_ADDRESS` to `pii_redact`'s enum → upgrade the PII pack's
   MAC rule from `justify` to `redact`.
4. Small, if healthcare is a near-term target: implement NPI's real
   checksum function instead of the keyword-heuristic stand-in.
5. Decision needed, not effort: Off-Policy Content / author-first semantic
   policies (§4) — ties to `feat/policy-starter-evidence-grounding`.
6. Redo the dashboard-side category/icon/test follow-up (§6) once these
   packs are ready to merge.
7. Only pursue if a real customer asks: the ~16 excluded secret types
   (§1) and the six semantic Healthcare categories (§3) — both need either
   verified real-world formats or an NER/LLM capability that doesn't exist
   yet, not more guessing.
