# Speakeasy Gram "Built-in detector" catalog — full reference

Source: live walkthrough of `app.getgram.ai`'s standard-policy "Detect" step
(2026-09-11 and 2026-09-15), every category toggled on and every
"Customize" sub-panel opened and read in full. This is the complete,
verified rule taxonomy — every count below was cross-checked against the
count badge the UI itself displayed (e.g. "33/33"), not estimated.

This doc is a **reference catalog**, not pack files. It exists so building
Tracelet pack JSON later (or deciding not to, where equivalent coverage
already exists) is an informed choice rather than a guess. See
`speakeasy-parity-gap-analysis.md` for what's already been decided/shipped
vs. what's still open.

There are 2 policy types (Built-in detector, Prompt-based) and, under
Built-in detector, 11 categories. This doc covers all 11.

---

## 1. Secrets — 222 rules across 12 subcategories

All 222 verified individually. Sum check: 30+33+14+25+23+10+8+14+12+14+31+8
= 222. ✓ These are gitleaks rule display names (confirmed: identical
naming to the public gitleaks default ruleset), so Tracelet's own
`secret_detection` rule type (embedded gitleaks, ~195 rules) already has
near-total detection parity — this table is for cross-referencing coverage
and for eventually building a Tracelet-side rule-browser UI, not for
authoring a new pack from scratch.

### Cloud & Infrastructure (30)
Alibaba Access Key ID · Alibaba Secret Key · AWS Credentials · Amazon
Bedrock API Key (Long-Lived) · Amazon Bedrock API Key (Short-Lived) · Azure
AD Client Secret · Cisco Meraki API Key · Cloudflare API Key · Cloudflare
Global API Key · Cloudflare Origin Ca Key · Digitalocean Access Token ·
Digitalocean PAT · Digitalocean Refresh Token · Fastly API Token · Fly.io
Access Token · GCP API Key · HashiCorp Terraform API Token · HashiCorp
Terraform Password · Heroku API Key · Heroku API Key (v2) · Kubernetes
Secret (YAML) · Netlify Access Token · Openshift User Token · Pulumi API
Token · Scalingo API Token · Vault Batch Token · Vault Service Token ·
Yandex Access Token · Yandex API Key · Yandex Aws Access Token

### Source Control & Packages (33)
Artifactory API Key · Artifactory Reference Token · Bitbucket Client ID ·
Bitbucket Client Secret · Clojars API Token · GitHub App Token · GitHub
Fine-Grained PAT · GitHub OAuth Token · GitHub Personal Access Token ·
GitHub Refresh Token · GitLab CI/CD Job Token · GitLab Deploy Token ·
GitLab Feature Flag Token · GitLab Feed Token · GitLab Incoming Mail Token
· GitLab K8s Agent Token · GitLab OAuth App Secret · GitLab Personal
Access Token · GitLab PAT (Routable) · GitLab Pipeline Trigger Token ·
GitLab Runner Registration Token · GitLab Runner Auth Token · GitLab
Runner Auth Token (Routable) · GitLab SCIM Token · GitLab Session Cookie
· Jfrog API Key · Jfrog Identity Token · npm Access Token · NuGet Config
Password · Postman API Token · PyPI Upload Token · Rubygems API Token ·
Sourcegraph Access Token

### CI & DevOps (14)
Codecov Access Token · Doppler API Token · Droneci Access Token · Harness
API Key · Infracost API Token · Launchdarkly Access Token · Octopus Deploy
API Key · Prefect API Token · Rapidapi Access Token · Sidekiq Secret ·
Sidekiq Sensitive URL · Snyk API Token · Sonar API Token · Travisci Access
Token

### Payments & Fintech (25)
Bittrex Access Key · Bittrex Secret Key · Coinbase Access Token · Duffel
API Token · Easypost API Token · Easypost Test API Token · Finicity API
Token · Finicity Client Secret · Finnhub Access Token · Flutterwave
Encryption Key · Flutterwave Public Key · Flutterwave Secret Key ·
Freshbooks Access Token · Gocardless API Token · Kraken Access Token ·
Kucoin Access Token · Kucoin Secret Key · Lob API Key · Lob Pub API Key ·
Plaid API Token · Plaid Client ID · Plaid Secret Key · Shippo API Token ·
Square Access Token · Stripe Access Token

### Communication (23)
Beamer API Token · Discord API Token · Discord Client ID · Discord Client
Secret · Gitter Access Token · Intercom API Key · Mattermost Access Token
· Messagebird API Token · Messagebird Client ID · Sendbird Access ID ·
Sendbird Access Token · Slack App Token · Slack Bot Token · Slack Config
Access Token · Slack Config Refresh Token · Slack Legacy Bot Token · Slack
Legacy Token · Slack Legacy Workspace Token · Slack User Token · Slack
Webhook URL · Telegram Bot API Token · Twilio API Key · Zendesk Secret Key

### Email & Marketing (10)
Contentful Delivery API Token · Freemius Secret Key · Hubspot API Key ·
Mailchimp API Key · Mailgun Private API Token · Mailgun Pub Key · Mailgun
Signing Key · Sendgrid API Token · Sendinblue API Token · Typeform API
Token

### AI & ML (8)
Anthropic Admin API Key · Anthropic API Key · Cohere API Token · Hugging
Face Access Token · Hugging Face Org API Token · OpenAI API Key ·
Perplexity API Key · Privateai API Token

### Observability (14)
Datadog Access Token · Dynatrace API Token · Grafana API Key · Grafana
Cloud API Token · Grafana Service Account Token · New Relic Browser API
Token · New Relic Insert Key · New Relic User API ID · New Relic User API
Key · Sentry Access Token · Sentry Org Token · Sentry User Token ·
Sumologic Access ID · Sumologic Access Token

### Data & Analytics (12)
Algolia API Key · ClickHouse Cloud API Key · Confluent Access Token ·
Confluent Secret Key · Databricks API Token · Looker Client ID · Looker
Client Secret · Mapbox API Token · Maxmind License Key · Planetscale API
Token · Planetscale OAUTH Token · Planetscale Password

### Identity & Auth (14)
1Password Secret Key · 1Password Service Account Token · Adobe Client ID
· Adobe Client Secret · Age Secret Key · Atlassian API Token · Authress
Service Client Access Key · Intra42 Client Secret · JSON Web Token (JWT) ·
JSON Web Token (Base64) · Microsoft Teams Webhook · Okta Access Token ·
PKCS #12 File · Private Key (RSA/EC/DSA/SSH)

### Productivity & SaaS (31)
Airtable API Key · Airtable Personal Access Token · Asana Client ID ·
Asana Client Secret · Dropbox API Token · Dropbox Long Lived API Token ·
Dropbox Short Lived API Token · Etsy Access Token · Facebook Access Token
· Facebook Page Access Token · Facebook Secret · Flickr Access Token ·
Frameio API Token · Linear API Key · Linear Client Secret · Linkedin
Client ID · Linkedin Client Secret · Notion API Token · NY Times Access
Token · Readme API Token · Shopify Access Token · Shopify Custom Access
Token · Shopify Private App Access Token · Shopify Shared Secret ·
Squarespace Access Token · Twitch API Token · Twitter Access Secret ·
Twitter Access Token · Twitter API Key · Twitter API Secret · Twitter
Bearer Token

### Other (8)
Adafruit API Key · curl Authorization Header · curl Basic Auth · Defined
Networking API Token · Generic API Key · SettleMint Application Token ·
SettleMint Personal Token · SettleMint Service Token

---

## 2. Financial Information — 4 rules (fully verified)
Credit card number (12-19 digits) · International Bank Account Number ·
US bank account number (8-17 digits) · Bitcoin wallet address

→ Shipped as `packs/financial-baseline.json`.

## 3. Personal Identifiable Information — 4 rules (fully verified)
Email address · Telephone number · IPv4 or IPv6 address · Network
interface identifier (MAC)

→ Shipped as `packs/pii-baseline.json`.

## 4. Government Identifiers — 12 rules (fully verified)
US Social Security Number · US passport number (9 digits) · US Individual
Taxpayer ID Number · UK National Health Service number · UK National
Insurance Number · UK passport number · Spain personal tax ID (NIF) ·
Italy personal identification code · Australia Tax File Number · India
Permanent Account Number · India Aadhaar (12-digit identity) · Singapore
NRIC / FIN

→ Shipped as `packs/government-id-baseline.json`, **US-only subset**
(SSN, passport, ITIN — 3 of the 12). The other 9 (all non-US) are listed
here for completeness but not yet built; see gap-analysis doc §2.

## 5. Healthcare Information — 9 rules (fully verified)
Common medical license numbers · US Medicare Beneficiary Identifier · US
National Provider Identifier · Disease or disorder mention · Medication
or drug name · Treatment or diagnostic procedure · Clinical event mention
· Biological attribute or measurement · Family medical history reference

→ Shipped as `packs/healthcare-id-baseline.json`, **1 of 9** (Medicare
Beneficiary Identifier only). The other 8 are deliberately excluded — see
gap-analysis doc §3 for why each one specifically doesn't meet the bar for
a confident regex rule.

## 6. Off-Policy Content — 4 rules, NOT inspectable
Labeled "Coming soon" in the product itself — its toggle is disabled, so
there's no "Customize" panel to open. The 4-rule count is displayed but
the rules themselves are not visible in the UI at all; this isn't a gap in
our research, it's a gap in what the product currently exposes. Described
as: "Requests that violate usage policies or acceptable use guidelines."

## 7. Non-Corporate Accounts — 2 rules (fully verified)
Personal AI account · Unapproved email domain (backed by a configurable,
exact-match "approved email domains" allowlist — sessions from domains not
on the list are flagged; until at least one domain is configured, only the
personal-account rule fires)

→ Not built (needs a new session/identity-level rule type; see gap-analysis
doc §5).

## 8. Shadow MCP — no fixed rule list
"Tool calls that don't come from a Speakeasy-issued MCP server. Requires
Speakeasy hooks to be installed on the agent." No rule count is shown and
no "Customize" panel exists — this is a provenance check (is this call
coming through our proxy or not), not an enumerable rule set.

## 9. Destructive Tools — no fixed rule list
"MCP tool calls whose platform tool definition is annotated as destructive.
Requires Speakeasy hooks and platform-issued MCP tool metadata." Driven by
consuming the MCP tool definition's own `destructiveHint`-style annotation,
not a static pattern list.

## 10. Destructive CLI Commands — no fixed rule list
"Tool calls whose arguments match a curated set of destructive shell, git,
database, or cloud CLI patterns (rm -rf, git push --force, DROP TABLE,
kubectl delete ns, ...). Applies to native Bash / run_terminal_cmd as well
as MCP-routed tools whose arguments carry destructive content." No rule
count or Customize panel — internally curated, not user-browsable. Already
far exceeded by Tracelet's 46 packs / hundreds of rules in this repo.

## 11. Prompt Injection — no fixed rule list
"Jailbreaks, instruction overrides, and prompt extraction — in a user
prompt or smuggled through tool outputs. Evaluated semantically by an LLM
judge." No rule count — this is judge-based, not pattern-based.

---

## Coverage summary

| # | Category | Rules | Enumerated? | Tracelet pack status |
|---|---|---|---|---|
| 1 | Secrets | 222 | ✅ all 222 | Diffed against the real 195-rule gitleaks config: ~25 genuine gaps found, 9 shipped (`secrets-coverage-gap-guard.json`), ~16 deliberately excluded (no safe format) |
| 2 | Financial Information | 4 | ✅ all 4 | Shipped, all 4 (`financial-baseline.json`) |
| 3 | PII | 4 | ✅ all 4 | Shipped, all 4 (`pii-baseline.json`) |
| 4 | Government Identifiers | 12 | ✅ all 12 | Shipped, **all 12** (`government-id-baseline.json`) — non-US rules are format heuristics, no checksum validation |
| 5 | Healthcare Information | 9 | ✅ all 9 | Shipped, **all 9** (`healthcare-id-baseline.json`) at 3 explicit confidence tiers — see gap-analysis §3 |
| 6 | Off-Policy Content | 4 | ❌ product doesn't expose them | N/A |
| 7 | Non-Corporate Accounts | 2 | ✅ both | Both drafted with verified (compiled+evaluated) Rego in `docs/drafts/`; not yet installable — needs one small, identified engine change (see gap-analysis §5), not a new rule type |
| 8 | Shadow MCP | n/a | n/a (no fixed list) | Not applicable as a pack |
| 9 | Destructive Tools | n/a | n/a (no fixed list) | Not applicable as a pack |
| 10 | Destructive CLI Commands | n/a | n/a (no fixed list) | Already exceeded (46 packs) |
| 11 | Prompt Injection | n/a | n/a (no fixed list) | Already covered (audit matchers) |

Everything marked ✅ above is genuinely complete — not sampled, not
assumed. The only category with any remaining "we can't see it" gap is
Off-Policy Content (§6), and that's a limitation of the competitor's own
product (disabled/coming-soon), not of this research. Every buildable rule
across categories 2-5 and 7 is now either a real pack rule or an
individually-reasoned, explicit exclusion — see
`speakeasy-parity-gap-analysis.md` for every exclusion's specific reason.
