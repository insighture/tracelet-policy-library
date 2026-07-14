#!/usr/bin/env python3
"""Generate tracelet policy packs from a dcg corpus (see extract.py).

Maps dcg destructive patterns to tracelet command_filter rules:

    severity  -> action / fail_mode      priority band
    critical  -> request_access / closed 100+
    high      -> justify        / closed 200+
    medium    -> warn           / open   300+
    low       -> log            / open   400+

dcg pack-level safe patterns become allowed_patterns on every rule generated
from that pack (same semantics: dcg checks safe patterns first and skips the
whole pack on a match).

Regex handling: patterns must compile under Go RE2 (tracelet's engine).
- `(?<name>` is rewritten to `(?P<name>`.
- A lookahead at the very end of a pattern is rewritten to a consuming group.
- Any other lookaround must have a manual replacement in REGEX_OVERRIDES,
  otherwise the pattern is reported and the rule is skipped.

Usage:
    python generate.py <corpus.json> <library-root>
"""

import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Wave 1 pack composition
# ---------------------------------------------------------------------------

WAVE1 = [
    {
        "id": "postgresql-guard",
        "name": "PostgreSQL Guard",
        "category": "database",
        "sources": ["database.postgresql"],
        "description": "Deep PostgreSQL protection: DROP DATABASE/TABLE/SCHEMA, TRUNCATE, unqualified DELETE, dropdb, and destructive pg_dump --clean restores. Complements Database Baseline with engine-specific coverage. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "mysql-guard",
        "name": "MySQL Guard",
        "category": "database",
        "sources": ["database.mysql"],
        "description": "Deep MySQL/MariaDB protection: DROP and TRUNCATE statements, mysqladmin drop, destructive mysqldump flags, and unqualified DELETE/UPDATE. Complements Database Baseline with engine-specific coverage. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "mongodb-guard",
        "name": "MongoDB Guard",
        "category": "database",
        "sources": ["database.mongodb"],
        "description": "MongoDB protection: dropDatabase, collection drops, deleteMany without filters, and destructive mongorestore --drop. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "redis-guard",
        "name": "Redis Guard",
        "category": "database",
        "sources": ["database.redis"],
        "description": "Redis protection: FLUSHALL/FLUSHDB, CONFIG REWRITE, destructive key operations, and cluster reset commands. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "sqlite-guard",
        "name": "SQLite Guard",
        "category": "database",
        "sources": ["database.sqlite"],
        "description": "SQLite protection: DROP/DELETE statements through the sqlite3 CLI and destructive database file operations. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "supabase-guard",
        "name": "Supabase Guard",
        "category": "database",
        "sources": ["database.supabase"],
        "description": "Supabase CLI protection: project deletion, database resets, branch deletion, secret removal, and destructive migration commands. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "aws-extended",
        "name": "AWS Extended",
        "category": "aws",
        "sources": ["cloud.aws"],
        "description": "Extended AWS CLI protection beyond AWS Baseline: EC2/EBS/RDS deletion, S3 wipes, IAM and security-group changes, Lambda/ECS/EKS teardown, CloudFormation stack deletion, and more. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "kubernetes-extended",
        "name": "Kubernetes Extended",
        "category": "kubernetes",
        "sources": ["kubernetes.kubectl", "kubernetes.helm", "kubernetes.kustomize"],
        "description": "Extended Kubernetes protection beyond Kubernetes Baseline: broad kubectl delete/drain variants, destructive patches and scale-to-zero, helm rollback edge cases, and kustomize-driven deletions. Derived from the destructive_command_guard pattern library.",
        # helm uninstall/delete is already covered by kubernetes-baseline
        "exclude": {"kubernetes.helm": ["uninstall"]},
    },
    {
        "id": "docker-extended",
        "name": "Docker Extended",
        "category": "docker",
        "sources": ["containers.docker", "containers.compose", "containers.podman"],
        "description": "Extended container protection beyond Docker Baseline: docker/podman prune and force-removal variants, volume and network deletion, and docker compose down -v. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "git-strict",
        "name": "Git Strict",
        "category": "git",
        "sources": ["core.git", "strict_git"],
        "description": "Strict git hygiene for teams that want maximum protection: discarding working-tree changes (checkout --/restore), stash deletion, branch force-deletion, history rewrites (rebase, amend, filter-branch), reflog expiry, and indiscriminate git add. Complements Git Baseline (force-push and protected-branch rules live there). Derived from the destructive_command_guard pattern library.",
        # already covered by git-baseline
        "exclude": {
            "core.git": ["reset-hard", "clean-force", "push-force-long", "push-force-short"],
            "strict_git": ["push-force-any", "push-master", "push-main"],
        },
        # `git add .` at justify would be too noisy; keep as a warning
        "severity_overrides": {
            ("strict_git", "add-all-dot"): "medium",
            ("strict_git", "add-all-flag"): "medium",
        },
    },
    {
        "id": "secrets-managers-guard",
        "name": "Secrets Managers Guard",
        "category": "secrets",
        "sources": ["secrets.vault", "secrets.aws_secrets", "secrets.onepassword", "secrets.doppler"],
        "description": "Protects secret-manager CLIs: HashiCorp Vault seal/revoke/delete, AWS Secrets Manager deletion, 1Password item/vault removal, and Doppler secret deletion. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "terraform-extended",
        "name": "Terraform Extended",
        "category": "terraform",
        "sources": ["infrastructure.terraform"],
        "description": "Extended Terraform protection beyond Terraform Baseline: workspace deletion, force-unlock, taint, and destructive state manipulation. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "filesystem-extended",
        "name": "Filesystem Extended",
        "category": "filesystem",
        "sources": ["core.filesystem"],
        "description": "Extended filesystem protection beyond Filesystem Baseline: rm flag variants (-r -f, --recursive --force), find -delete, shred, truncate, tar --remove-files, dd file overwrites, unlink, and copy-then-delete exfiltration patterns on sensitive paths. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "disk-operations-guard",
        "name": "Disk Operations Guard",
        "category": "filesystem",
        "sources": ["system.disk"],
        "description": "Guards low-level disk operations: mkfs, fdisk/parted/sgdisk partitioning, wipefs, LVM/RAID teardown, swap manipulation, and filesystem-destroying tools. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "windows-guard",
        "name": "Windows Guard",
        "category": "filesystem",
        "sources": ["windows.filesystem", "windows.system", "windows.powershell", "windows.misc"],
        "description": "Windows-specific protection: del /s, rd /s, Remove-Item -Recurse -Force, format, diskpart, vssadmin delete shadows, registry deletion, and destructive PowerShell one-liners. Derived from the destructive_command_guard pattern library.",
    },
]

# ---------------------------------------------------------------------------
# Wave 2 pack composition — new categories; the dashboard's category
# filter/icon maps must list these (see isee dashboard
# governance.policy.tool-policies.tsx).
# ---------------------------------------------------------------------------

WAVE2 = [
    {
        "id": "gcp-guard",
        "name": "GCP Guard",
        "category": "gcp",
        "sources": ["cloud.gcp"],
        "description": "Protects Google Cloud: project/instance deletion, GCS bucket removal, GKE cluster teardown, IAM policy changes, and destructive gcloud/gsutil operations. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "azure-guard",
        "name": "Azure Guard",
        "category": "azure",
        "sources": ["cloud.azure"],
        "description": "Protects Microsoft Azure: resource-group and VM deletion, storage account removal, AKS teardown, key vault purges, and destructive az CLI operations. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "cicd-guard",
        "name": "CI/CD Guard",
        "category": "cicd",
        "sources": ["cicd.github_actions", "cicd.gitlab_ci", "cicd.jenkins", "cicd.circleci"],
        "description": "Protects CI/CD systems: deleting workflows, runners, pipelines, jobs, caches, and secrets across GitHub Actions, GitLab CI, Jenkins, and CircleCI. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "messaging-guard",
        "name": "Messaging Guard",
        "category": "messaging",
        "sources": ["messaging.kafka", "messaging.rabbitmq", "messaging.nats", "messaging.sqs_sns"],
        "description": "Protects message brokers: topic/queue deletion, consumer-group resets, exchange removal, and stream purges across Kafka, RabbitMQ, NATS, and SQS/SNS. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "search-guard",
        "name": "Search & Indexing Guard",
        "category": "search",
        "sources": ["search.elasticsearch", "search.opensearch", "search.algolia", "search.meilisearch"],
        "description": "Protects search clusters: index deletion, delete-by-query, snapshot removal, and cluster-settings changes across Elasticsearch, OpenSearch, Algolia, and Meilisearch. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "backup-guard",
        "name": "Backup Guard",
        "category": "backup",
        "sources": ["backup.restic", "backup.borg", "backup.rclone", "backup.velero"],
        "description": "Protects backup systems — the last line of defence: snapshot forgetting/pruning, repository deletion, rclone purge/delete, and Velero backup removal. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "dns-guard",
        "name": "DNS Guard",
        "category": "dns",
        "sources": ["dns.cloudflare", "dns.route53", "dns.generic"],
        "description": "Protects DNS: zone and record deletion across Cloudflare, Route 53, and generic DNS tooling. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "cdn-guard",
        "name": "CDN Guard",
        "category": "cdn",
        "sources": ["cdn.cloudflare_workers", "cdn.fastly", "cdn.cloudfront"],
        "description": "Protects CDN and edge platforms: worker/service deletion, distribution removal, and cache purges across Cloudflare Workers, Fastly, and CloudFront. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "monitoring-guard",
        "name": "Monitoring Guard",
        "category": "monitoring",
        "sources": ["monitoring.datadog", "monitoring.pagerduty", "monitoring.prometheus", "monitoring.newrelic", "monitoring.splunk"],
        "description": "Protects observability systems: deleting dashboards, monitors, alert rules, escalation policies, and retention data across Datadog, PagerDuty, Prometheus, New Relic, and Splunk. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "payment-guard",
        "name": "Payment Providers Guard",
        "category": "payment",
        "sources": ["payment.stripe", "payment.braintree", "payment.square"],
        "description": "Protects payment providers: deleting customers, subscriptions, webhooks, and products, and issuing refunds across Stripe, Braintree, and Square. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "github-guard",
        "name": "GitHub Platform Guard",
        "category": "platform",
        "sources": ["platform.github"],
        "description": "Protects GitHub via the gh CLI and API: repository deletion, release removal, deploy-key and webhook changes, and secret deletion. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "gitlab-guard",
        "name": "GitLab Platform Guard",
        "category": "platform",
        "sources": ["platform.gitlab"],
        "description": "Protects GitLab via the glab CLI and API: project deletion, release removal, and runner deregistration. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "deploy-platforms-guard",
        "name": "Deploy Platforms Guard",
        "category": "platform",
        "sources": ["platform.railway", "platform.kamal", "platform.modal"],
        "description": "Protects deployment platforms: project/service/environment deletion, volume wipes, variable removal, and app teardown across Railway, Kamal, and Modal. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "email-guard",
        "name": "Email Providers Guard",
        "category": "email",
        "sources": ["email.ses", "email.sendgrid", "email.mailgun", "email.postmark"],
        "description": "Protects transactional email providers: identity/domain deletion, template removal, suppression-list changes, and API-key deletion across SES, SendGrid, Mailgun, and Postmark. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "featureflags-guard",
        "name": "Feature Flags Guard",
        "category": "featureflags",
        "sources": ["featureflags.launchdarkly", "featureflags.split", "featureflags.flipt", "featureflags.unleash"],
        "description": "Protects feature-flag platforms: flag/segment deletion, environment removal, and project teardown across LaunchDarkly, Split, Flipt, and Unleash. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "loadbalancer-guard",
        "name": "Load Balancer Guard",
        "category": "loadbalancer",
        "sources": ["loadbalancer.nginx", "loadbalancer.elb", "loadbalancer.haproxy", "loadbalancer.traefik"],
        "description": "Protects load balancers and reverse proxies: config deletion, listener/target-group removal, and destructive reloads across nginx, ELB/ALB, HAProxy, and Traefik. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "apigateway-guard",
        "name": "API Gateway Guard",
        "category": "apigateway",
        "sources": ["apigateway.aws", "apigateway.kong", "apigateway.apigee"],
        "description": "Protects API gateways: API/stage/route deletion, consumer and plugin removal, and proxy undeployment across AWS API Gateway, Kong, and Apigee. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "iac-guard",
        "name": "IaC Tools Guard",
        "category": "infrastructure",
        "sources": ["infrastructure.pulumi", "infrastructure.ansible", "infrastructure.atmos"],
        "description": "Protects infrastructure-as-code tools beyond Terraform: pulumi destroy and stack removal, destructive ansible runs, and atmos terraform wrappers. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "package-managers-guard",
        "name": "Package Managers Guard",
        "category": "packages",
        "sources": ["package_managers"],
        "description": "Protects package registries and local package state: npm/yarn/pnpm unpublish and dist-tag changes, pip/cargo/gem yanks, and destructive global operations. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "remote-access-guard",
        "name": "Remote Access Guard",
        "category": "remote",
        "sources": ["remote.ssh", "remote.scp", "remote.rsync"],
        "description": "Protects remote hosts: destructive commands over ssh, overwriting remote files via scp, and rsync --delete mirroring. Derived from the destructive_command_guard pattern library.",
    },
    {
        "id": "system-services-guard",
        "name": "System Services Guard",
        "category": "system",
        "sources": ["system.permissions", "system.services"],
        "description": "Protects host system state: recursive chmod/chown on system paths, disabling or masking system services, and destructive systemctl operations. Derived from the destructive_command_guard pattern library.",
    },
]

ACTION_BY_SEVERITY = {
    "critical": ("request_access", "closed", 100),
    "high": ("justify", "closed", 200),
    "medium": ("warn", "open", 300),
    "low": ("log", "open", 400),
}

NAME_PREFIX = {
    "request_access": "Require access request for",
    "justify": "Require justification for",
    "warn": "Warn on",
    "log": "Log",
}

# Manual RE2 replacements for patterns using lookarounds that cannot be
# rewritten mechanically. Keyed by (dcg pack id, pattern name).
# Value: {"regex": <RE2 pattern>, "allow": [<extra allowed_patterns>]} or
# None to drop the rule (document why in a comment).
#
# dcg uses negative lookaheads like (?!.*--dry-run) to exempt safe variants;
# tracelet's command_filter has a native mechanism for exactly that —
# allowed_patterns override blocked_patterns — so the exemption moves there.
# Per-rule allows are hardened with a [^;&]*$ tail so they cannot be
# satisfied by one segment of a compound command while another segment does
# the destructive work (e.g. `kubectl delete x --dry-run=client; kubectl
# delete y`). Pipes stay allowed (dry-run output is often piped).
KUBECTL_DRY_RUN = r"--dry-run(?:=(?:client|server))?\b[^;&]*$"
HELM_DRY_RUN = r"--dry-run(?:=(?:true|client|server))?\b[^;&]*$"

REGEX_OVERRIDES: dict = {
    ("kubernetes.kubectl", "delete-workload"): {
        "regex": r"kubectl\b.*?\bdelete\s+(?:deployment|statefulset|daemonset|replicaset)\b",
        "allow": [KUBECTL_DRY_RUN],
    },
    ("kubernetes.kubectl", "delete-pvc"): {
        "regex": r"kubectl\b.*?\bdelete\s+(?:pvc|persistentvolumeclaim)\b",
        "allow": [KUBECTL_DRY_RUN],
    },
    ("kubernetes.kubectl", "delete-pv"): {
        "regex": r"kubectl\b.*?\bdelete\s+(?:pv|persistentvolume)\b",
        "allow": [KUBECTL_DRY_RUN],
    },
    ("kubernetes.helm", "rollback"): {
        "regex": r"helm\b.*?\brollback\b",
        "allow": [HELM_DRY_RUN],
    },
    ("kubernetes.kustomize", "kustomize-delete"): {
        "regex": r"kustomize\b.*?\bbuild\s+.*\|\s*kubectl\b.*?\bdelete",
        "allow": [KUBECTL_DRY_RUN],
    },
    ("kubernetes.kustomize", "kubectl-kustomize-delete"): {
        "regex": r"kubectl\b.*?\bkustomize\s+.*\|\s*kubectl\b.*?\bdelete",
        "allow": [KUBECTL_DRY_RUN],
    },
    ("kubernetes.kustomize", "kubectl-delete-k"): {
        "regex": r"kubectl\b.*?\bdelete\s+-k\b",
        "allow": [KUBECTL_DRY_RUN],
    },
    # (?!-b)(?!--orphan) exemptions move to allowed_patterns
    ("core.git", "checkout-ref-discard"): {
        "regex": r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*checkout\s+\S+\s+--\s+",
        "allow": [r"git\s+(?:\S+\s+)*checkout\s+(?:-b|--orphan)\b[^;&]*$"],
    },
    # (?!.*--staged) exemption moves to allowed_patterns
    ("core.git", "restore-worktree"): {
        "regex": r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*restore\s",
        "allow": [r"git\s+(?:\S+\s+)*restore\b[^|;&]*\s(?:--staged|-S)\b[^;&]*$"],
    },
    # original (?!/dev/) is redundant here: the sensitive-path alternation that
    # follows can never match a /dev/ path (dev is not in its directory list),
    # so the pattern only needs its boundary lookaheads converted (see
    # CONVERT_LOOKAHEADS handling below applied inline).
    ("core.filesystem", "dd-overwrite-root-home"): {
        "regex": r"\bdd\b[^|;&]*?\bof=['\"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|opt)(?:/|[\s\)'\"]|$)|/(?:[\s\)'\"]|$)|~(?:\s|$|/|\))|\$\{?HOME\b)",
    },
    # (?!/dev/) expressed as an RE2 prefix negation: of= followed by anything
    # that does not begin with /dev/ (writing to /dev/ is covered by the
    # filesystem-baseline dd rule).
    ("core.filesystem", "dd-overwrite-general"): {
        "regex": r"\bdd\b[^|;&]*?\bof=['\"\\]?(?:[^/\s]|/(?:$|[^d\s]|d(?:$|[^e\s]|e(?:$|[^v\s]|v(?:$|[^/\s])))))",
    },
    # Original uses a lookbehind to skip >> appends and a negative lookahead to
    # skip /dev/null|zero|full. Rewritten: consume the preceding character to
    # exclude >>, and drop `dev` from the directory list instead of negating
    # /dev/null (block-device writes are covered by the dd baseline rule).
    ("core.filesystem", "redirect-truncate-root-home"): {
        "regex": r"(?:^|[^<>])(?:&>|>&|[12]?>\|?)\s*(?:['\"\\]|\$['\"])?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|opt)(?:/|[\s\)'\"]|$)|~(?:/|\s|$)|\$\{?HOME\b)",
    },
    # (?!.*-l) exemption (fdisk -l just lists) moves to allowed_patterns
    ("system.disk", "fdisk-edit"): {
        "regex": r"fdisk\s+['\"]?/dev/",
        "allow": [r"fdisk\b[^|;&]*\s(?:-l|--list)\b[^;&]*$"],
    },
    # Original mixes negative lookaheads to exempt read-only subcommands.
    # Rewritten: block parted aimed at a device; allow the read-only forms.
    ("system.disk", "parted-modify"): {
        "regex": r"parted\b[^\n;&|]*?['\"]?/dev/",
        "allow": [r"parted\b[^|;&]*\s(?:-l|--list|align-check|help|print)\b[^;&]*$"],
    },
    # Two AND-ed lookaheads (both -Recurse and -Force, any order) expanded
    # into the two explicit orderings.
    ("windows.filesystem", "remove-item-recurse-force"): {
        "regex": r"(?i)\b(?:remove-item|rmdir|rd|ri|rm|del|erase)\b(?:[^|&\r\n]*\s(?:-recurse|-r)\b[^|&\r\n]*\s(?:-force|-f)\b|[^|&\r\n]*\s(?:-force|-f)\b[^|&\r\n]*\s(?:-recurse|-r)\b)",
    },
    # Trailing content assertion converted to a consuming match.
    ("windows.system", "diskpart"): {
        "regex": r"(?i)\bdiskpart(?:\.exe)?\b[^|&\r\n]*(?:/s\b|\bclean\b|\bdelete\b|\bformat\b)",
    },
    ("windows.misc", "robocopy-mirror"): {
        "regex": r"(?i)\brobocopy(?:\.exe)?\b[^|&\r\n]*\s(?:/mir|/purge)\b",
    },
    # --- Wave 2 ---
    # (?!.*--dry-run) exemptions on registry publishes move to allowed_patterns
    ("package_managers", "npm-publish"): {
        "regex": r"\bnpm\b.*?\bpublish\b",
        "allow": [r"--dry-run(?:=true)?\b[^;&]*$"],
    },
    ("package_managers", "yarn-publish"): {
        "regex": r"\byarn\b.*?\bpublish\b",
        "allow": [r"--dry-run(?:=true)?\b[^;&]*$"],
    },
    ("package_managers", "pnpm-publish"): {
        "regex": r"\bpnpm\b.*?\bpublish\b",
        "allow": [r"--dry-run(?:=true)?\b[^;&]*$"],
    },
    ("package_managers", "cargo-publish"): {
        "regex": r"\bcargo\b.*?\bpublish\b",
        "allow": [r"--dry-run(?:=true)?\b[^;&]*$"],
    },
    ("package_managers", "poetry-publish"): {
        "regex": r"\bpoetry\b.*?\bpublish\b",
        "allow": [r"--dry-run(?:=true)?\b[^;&]*$"],
    },
    # (?!.*(--check|--limit)) exemption moves to allowed_patterns
    ("infrastructure.ansible", "playbook-all-hosts"): {
        "regex": r"ansible-playbook\s+.*-i\s+\S+\s+\S+\.ya?ml",
        "allow": [r"ansible-playbook\b[^|;&]*(?:--check\b|--limit\b)[^;&]*$"],
    },
    # dcg splits volume rm into non-recursive (this) and recursive (separate
    # rule) via a negative lookahead; the recursive form moves to an allow so
    # only the dedicated recursive rule fires for it.
    ("platform.modal", "modal-volume-rm"): {
        "regex": r"(?:^|[^\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+rm\b",
        "allow": [r"modal\b[^|;&\r\n]*\bvolume\s+rm\b(?:[^;&|\r\n]|\\\r?\n)*(?:\s|=)(?:-r\b|-R\b|--recursive\b)[^;&]*$"],
    },
}

# Patterns whose positive lookaheads are all pure boundary assertions
# ((?=[\s)'"]|$) after a path) followed by absorbing context ([^|;&]*? etc.),
# verified safe to convert to consuming groups wholesale.
CONVERT_LOOKAHEADS = {
    ("core.filesystem", "cp-sensitive-then-delete"),
    ("core.filesystem", "ln-symlink-sensitive-then-delete"),
    ("core.filesystem", "rsync-sensitive-then-delete"),
    ("core.filesystem", "find-delete-root-home"),
    ("core.filesystem", "unlink-root-home"),
    ("core.filesystem", "truncate-zero-root-home"),
    ("core.filesystem", "shred-root-home"),
    ("core.filesystem", "tar-remove-files-root-home"),
    ("core.filesystem", "mv-sensitive-source-root-home"),
}

# Chunk size when folding a pack's safe patterns into allowed_patterns strings.
SAFE_CHUNK = 6

# A pack-level safe pattern is attached to every rule in the pack, so an
# unanchored one can be satisfied by a harmless segment of a compound command
# while another segment is destructive (`git checkout -b tmp && git stash
# clear`). Only start-anchored safelists (optionally after an inline flag
# group) are safe to attach pack-wide; the rest are dropped as redundant —
# the blocked patterns they exempt are subcommand-specific already.
ANCHORED = re.compile(r"^(?:\(\?[a-zA-Z]+\))?\^")

LOOKAROUND = re.compile(r"\(\?<?[=!]")


# dcg's `..`-path-traversal guards on /tmp-style safelists, replaced by a
# positive "no two consecutive dots" form (quantifier preserved). Strictly
# narrower than the original, so conversion can only make the safelist prompt
# MORE, never less.
TRAVERSAL_GUARDS = [
    (re.escape(r"(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))") + r"\\S([*+])",
     lambda m: r"(?:[^\s.]|\.[^\s.])" + m.group(1)),
    (re.escape(r'(?!(?:[^"]*/)?\.\.(?:/|"))') + r"\[\^\"\]([*+])",
     lambda m: r'(?:[^".]|\.[^".])' + m.group(1)),
]

# Manual RE2 replacements for safe patterns. Value None = drop.
SAFE_OVERRIDES: dict = {
    # -WhatIf makes these cmdlets preview-only; the original asserts -recurse
    # AND -force via lookaheads, but exempting any of the cmdlets with -whatif
    # is safe (the flag itself guarantees a dry run).
    ("windows.filesystem", "whatif-preview"): (
        r"(?i)^\s*(?:remove-item|ri|rm|rd|rmdir|del|erase|clear-content|clc|clear-recyclebin)\b"
        r"[^|&;\r\n]*\s-whatif\b[^|&;\r\n]*$"
    ),
}


def convert_trailing_lookahead(pattern: str) -> str:
    """Convert a positive lookahead that spans to the end of the pattern into
    a consuming group (safe: nothing follows it to re-match the input)."""
    idx = pattern.rfind("(?=")
    if idx == -1:
        return pattern
    depth = 0
    j = idx
    while j < len(pattern):
        c = pattern[j]
        if c in "()" and (j == 0 or pattern[j - 1] != "\\"):
            depth += 1 if c == "(" else -1
            if depth == 0:
                if j == len(pattern) - 1:
                    return pattern[:idx] + "(?:" + pattern[idx + 3 :]
                return pattern
        j += 1
    return pattern


def rewrite_re2(pattern: str):
    """Return (rewritten, ok). Mechanical fixes for RE2 compatibility."""
    # named groups: (?<name>  ->  (?P<name>
    pattern = re.sub(r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>", r"(?P<\1>", pattern)
    # word-ish lookbehind used to reject `my-railway` style prefixes ->
    # consuming equivalent (identical detection semantics for match-anywhere)
    pattern = pattern.replace(r"(?<![\w-])", r"(?:^|[^\w-])")
    for guard, replacement in TRAVERSAL_GUARDS:
        pattern = re.sub(guard, replacement, pattern)
    pattern = convert_trailing_lookahead(pattern)
    return pattern, not LOOKAROUND.search(pattern)


def scan_group(pattern: str, start: int):
    """Return the index just past the group opening at `start`, or None."""
    depth = 0
    j = start
    while j < len(pattern):
        c = pattern[j]
        if c in "()" and (j == 0 or pattern[j - 1] != "\\"):
            depth += 1 if c == "(" else -1
            if depth == 0:
                return j + 1
        j += 1
    return None


def convert_curl_and(pattern: str):
    """Convert `PREFIX(?=.*A)(?=.*B)....*` (AND-of-contents lookaheads) into
    an explicit ordering expansion `PREFIX(?:.*A.*B|.*B.*A|...)`.

    Slightly narrower than the original when A and B could overlap in the
    command text; for the method-flag + URL patterns this uses, they cannot.
    """
    idx = pattern.find("(?=")
    if idx == -1:
        return None
    prefix = pattern[:idx]
    if LOOKAROUND.search(prefix):
        return None
    parts = []
    pos = idx
    while pattern.startswith("(?=", pos):
        end = scan_group(pattern, pos)
        if end is None:
            return None
        content = pattern[pos + 3 : end - 1]
        if not content.startswith(".*") or LOOKAROUND.search(content):
            return None
        parts.append(content[2:])
        pos = end
    if pattern[pos:] not in ("", ".*", ".*$") or not parts or len(parts) > 3:
        return None
    from itertools import permutations
    alts = ["".join(".*" + p for p in perm) for perm in permutations(parts)]
    return prefix + "(?:" + "|".join(alts) + ")"


def convert_gh_flagskip(pattern: str):
    """Replace dcg's gh-CLI flag-skipper construct — `gh(?:\\s+--?FLAG
    (?:\\s+(?!KEYWORDS)VALUE)?)*` — with `\\bgh\\b[^|;&]*?`. The construct
    exists to stop a flag's value from consuming the subcommand keyword; the
    replacement just scans forward within the same shell segment.
    """
    if not pattern.startswith("gh(?:"):
        return None
    end = scan_group(pattern, 2)
    if end is None or end >= len(pattern) or pattern[end] != "*":
        return None
    candidate = r"\bgh\b[^|;&]*?" + pattern[end + 1 :]
    if LOOKAROUND.search(candidate):
        return None
    return candidate


def humanize(name: str) -> str:
    return name.replace("-", " ").replace("_", " ")


def build_rule(dcg_pack: str, pat: dict, priority: int, allowed: list[str]) -> dict:
    action, fail_mode, _ = ACTION_BY_SEVERITY[pat["severity"]]
    desc = pat["reason"].strip()
    if pat["suggestions"]:
        s = pat["suggestions"][0]
        desc = f"{desc} Safer alternative: `{s['command']}` — {s['note']}."
    rule = {
        "name": f"{NAME_PREFIX[action]} {humanize(pat['name'])}",
        "description": desc,
        "action": action,
        "fail_mode": fail_mode,
        "severity": pat["severity"],
        "priority": priority,
        "rule_type": "command_filter",
        "rule_config": {"blocked_patterns": [pat["regex_re2"]]},
        "events": ["pre_tool_use"],
        "tools": ["Bash"],
    }
    all_allowed = pat.get("extra_allow", []) + allowed
    if all_allowed:
        rule["rule_config"]["allowed_patterns"] = all_allowed
    return rule


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    corpus = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    root = Path(sys.argv[2])

    # index corpus by dcg pack id
    by_pack: dict[str, dict] = {}
    for f in corpus["files"].values():
        for pid in f["pack_ids"]:
            by_pack[pid] = f

    flagged = []       # (pack, name, regex) needing manual override
    dropped_safe = []  # safe patterns dropped for lookarounds

    generated = []
    for spec in WAVE1 + WAVE2:
        exclude = spec.get("exclude", {})
        sev_over = spec.get("severity_overrides", {})

        rules = []
        band_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for src in spec["sources"]:
            fdata = by_pack[src]
            # fold this dcg pack's safe patterns into allowed_patterns chunks
            safe_ok = []
            for sp in fdata["safe"]:
                skey = (src, sp["name"])
                if skey in SAFE_OVERRIDES:
                    if SAFE_OVERRIDES[skey] is not None:
                        safe_ok.append(SAFE_OVERRIDES[skey])
                    continue
                rx, ok = rewrite_re2(sp["regex"])
                if ok and ANCHORED.match(rx):
                    safe_ok.append(rx)
                elif not ok:
                    dropped_safe.append((src, sp["name"], sp["regex"]))
            allowed = [
                "|".join(f"(?:{p})" for p in safe_ok[i : i + SAFE_CHUNK])
                for i in range(0, len(safe_ok), SAFE_CHUNK)
            ]

            for pat in fdata["destructive"]:
                if pat["name"] in exclude.get(src, []):
                    continue
                sev = sev_over.get((src, pat["name"]), pat["severity"])
                pat = {**pat, "severity": sev}

                key = (src, pat["name"])
                if key in REGEX_OVERRIDES:
                    override = REGEX_OVERRIDES[key]
                    if override is None:
                        continue
                    pat["regex_re2"] = override["regex"]
                    pat["extra_allow"] = override.get("allow", [])
                    if LOOKAROUND.search(pat["regex_re2"]):
                        raise ValueError(f"override for {key} still has lookarounds")
                elif key in CONVERT_LOOKAHEADS:
                    rx = pat["regex"].replace("(?=", "(?:")
                    if LOOKAROUND.search(rx):
                        raise ValueError(f"{key} has non-positive lookarounds; needs a full override")
                    pat["regex_re2"] = rx
                else:
                    rx, ok = rewrite_re2(pat["regex"])
                    if not ok:
                        for conv in (convert_gh_flagskip, convert_curl_and):
                            alt = conv(rx)
                            if alt is not None:
                                rx, ok = alt, True
                                break
                    if not ok:
                        flagged.append((src, pat["name"], pat["regex"]))
                        continue
                    pat["regex_re2"] = rx

                _, _, base = ACTION_BY_SEVERITY[sev]
                priority = base + 10 * band_counts[sev]
                band_counts[sev] += 1
                rules.append(build_rule(src, pat, priority, allowed))

        # stable order: by priority, preserving insertion order within a band
        rules.sort(key=lambda r: r["priority"])
        # de-duplicate rule names across merged sources
        seen = {}
        for r in rules:
            if r["name"] in seen:
                seen[r["name"]] += 1
                r["name"] = f"{r['name']} ({seen[r['name']]})"
            else:
                seen[r["name"]] = 1

        pack = {
            "id": spec["id"],
            "name": spec["name"],
            "category": spec["category"],
            "description": spec["description"],
            "version": "1.0.0",
            "rules": rules,
        }
        out = root / "packs" / f"{spec['id']}.json"
        out.write_text(json.dumps(pack, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        generated.append((spec, len(rules)))
        print(f"wrote packs/{spec['id']}.json  ({len(rules)} rules)")

    # update index.json
    index_path = root / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    new_ids = {s["id"] for s, _ in generated}
    index["packs"] = [p for p in index["packs"] if p["id"] not in new_ids]
    for spec, count in generated:
        index["packs"].append({
            "id": spec["id"],
            "name": spec["name"],
            "category": spec["category"],
            "description": spec["description"],
            "version": "1.0.0",
            "rule_count": count,
        })
    index_path.write_text(json.dumps(index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"updated index.json  ({len(index['packs'])} packs total)")

    if flagged:
        print(f"\n{len(flagged)} destructive patterns need manual RE2 overrides (rules skipped):")
        for src, name, rx in flagged:
            print(f"  {src} / {name}\n      {rx}")
    if dropped_safe:
        print(f"\n{len(dropped_safe)} safe patterns dropped (lookarounds, no RE2 equivalent):")
        for src, name, _ in dropped_safe:
            print(f"  {src} / {name}")


if __name__ == "__main__":
    main()
