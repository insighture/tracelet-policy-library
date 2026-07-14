package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// evaluate mirrors the tracelet agent's command_filter semantics: a rule
// fires when any blocked pattern matches the original or lowercased command
// and no allowed pattern matches.
func evaluate(t *testing.T, p pack, command string) []string {
	t.Helper()
	lower := strings.ToLower(command)
	var fired []string
	for _, r := range p.Rules {
		if r.RuleType != "command_filter" {
			continue
		}
		var pc patternConfig
		if err := json.Unmarshal(r.RuleConfig, &pc); err != nil {
			t.Fatalf("%s/%s: %v", p.ID, r.Name, err)
		}
		blocked := false
		for _, rx := range pc.BlockedPatterns {
			re := regexp.MustCompile(rx)
			if re.MatchString(command) || re.MatchString(lower) {
				blocked = true
				break
			}
		}
		if !blocked {
			continue
		}
		allowed := false
		for _, rx := range pc.AllowedPatterns {
			re := regexp.MustCompile(rx)
			if re.MatchString(command) || re.MatchString(lower) {
				allowed = true
				break
			}
		}
		if !allowed {
			fired = append(fired, r.Name)
		}
	}
	return fired
}

func loadPack(t *testing.T, id string) pack {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "packs", id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var p pack
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGeneratedPackBehavior(t *testing.T) {
	cases := []struct {
		pack    string
		command string
		fires   bool
	}{
		// postgresql-guard
		{"postgresql-guard", "psql -c 'DROP DATABASE prod'", true},
		{"postgresql-guard", "dropdb production", true},
		{"postgresql-guard", "psql -c 'SELECT count(*) FROM users'", false},
		{"postgresql-guard", "pg_dump mydb > backup.sql", false},

		// mysql-guard
		{"mysql-guard", "mysql -e 'TRUNCATE TABLE orders'", true},
		{"mysql-guard", "mysql -e 'SHOW TABLES'", false},

		// redis-guard
		{"redis-guard", "redis-cli FLUSHALL", true},
		{"redis-guard", "redis-cli GET mykey", false},

		// aws-extended
		{"aws-extended", "aws ec2 terminate-instances --instance-ids i-0abc", true},
		{"aws-extended", "aws ec2 describe-instances", false},

		// kubernetes-extended: dry-run exemption moved to allowed_patterns
		{"kubernetes-extended", "kubectl delete deployment web", true},
		{"kubernetes-extended", "kubectl delete deployment web --dry-run=client", false},
		{"kubernetes-extended", "kubectl get pods", false},
		{"kubernetes-extended", "helm rollback myapp 3", true},

		// docker-extended
		{"docker-extended", "docker compose down -v", true},
		{"docker-extended", "docker compose up -d", false},

		// git-strict: -b / --staged exemptions moved to allowed_patterns
		{"git-strict", "git checkout main -- src/app.ts", true},
		{"git-strict", "git checkout -b feature/foo", false},
		{"git-strict", "git restore src/app.ts", true},
		{"git-strict", "git restore --staged src/app.ts", false},
		{"git-strict", "git stash clear", true},
		{"git-strict", "git status", false},

		// terraform-extended
		{"terraform-extended", "terraform workspace delete staging", true},
		{"terraform-extended", "terraform plan", false},

		// secrets-managers-guard
		{"secrets-managers-guard", "vault kv destroy secret/app", true},
		{"secrets-managers-guard", "vault kv get secret/app", false},

		// filesystem-extended: /tmp safelist survived RE2 conversion
		{"filesystem-extended", "rm -rf ./build", true},
		{"filesystem-extended", "rm -rf /tmp/build", false},
		{"filesystem-extended", "rm -rf /tmp/../etc", true},
		{"filesystem-extended", "find /etc -name '*.conf' -delete", true},
		{"filesystem-extended", "shred -u ~/.ssh/id_rsa", true},
		{"filesystem-extended", "ls -la /etc", false},

		// disk-operations-guard: fdisk -l exemption moved to allowed_patterns
		{"disk-operations-guard", "mkfs.ext4 /dev/sdb1", true},
		{"disk-operations-guard", "fdisk /dev/sda", true},
		{"disk-operations-guard", "fdisk -l /dev/sda", false},

		// windows-guard: -WhatIf preview exemption
		{"windows-guard", "Remove-Item -Recurse -Force C:\\temp\\build", true},
		{"windows-guard", "Remove-Item -Recurse -Force C:\\temp\\build -WhatIf", false},
		{"windows-guard", "vssadmin delete shadows /all", true},
		{"windows-guard", "Get-ChildItem C:\\temp", false},

		// --- Wave 2 ---
		{"gcp-guard", "gcloud projects delete my-project", true},
		{"gcp-guard", "gcloud compute instances list", false},
		{"azure-guard", "az group delete -n prod-rg --yes", true},
		{"azure-guard", "az vm list", false},

		// gh-flagskip conversion
		{"cicd-guard", "gh secret delete DEPLOY_KEY", true},
		{"cicd-guard", "gh --repo owner/repo secret delete DEPLOY_KEY", true},
		{"cicd-guard", "gh secret list", false},
		{"github-guard", "gh repo delete owner/repo --yes", true},
		{"github-guard", "gh repo view owner/repo", false},

		// curl-AND conversion: both flag orders must match
		{"search-guard", "curl -X DELETE http://elastic:9200/my-index", true},
		{"search-guard", "curl http://elastic:9200/my-index -X DELETE", true},
		{"search-guard", "curl -X GET http://elastic:9200/_cat/indices", false},
		{"monitoring-guard", "curl -X DELETE https://api.datadoghq.com/api/v1/dashboard/abc", true},

		// lookbehind conversion
		{"deploy-platforms-guard", "railway down", true},
		{"deploy-platforms-guard", "modal volume rm my-vol", true},
		{"deploy-platforms-guard", "modal volume rm -r my-vol", true},
		{"deploy-platforms-guard", "railway status", false},

		// publish dry-run exemption moved to allowed_patterns
		{"package-managers-guard", "npm publish", true},
		{"package-managers-guard", "npm publish --dry-run", false},
		{"iac-guard", "pulumi destroy --yes", true},
		{"iac-guard", "ansible-playbook -i inventory.ini site.yml", true},
		{"iac-guard", "ansible-playbook --check -i inventory.ini site.yml", false},
		{"backup-guard", "restic forget --prune", true},

		// compound-command bypass attempts: a harmless segment must not
		// exempt a destructive one
		{"kubernetes-extended", "kubectl delete deployment web --dry-run=client; kubectl delete deployment api", true},
		{"git-strict", "git checkout -b tmp && git stash clear", true},
		{"git-strict", "git restore --staged a && git restore b", true},
		{"filesystem-extended", "rm -rf /tmp/build && rm -rf ~/src", true},
		{"disk-operations-guard", "fdisk -l /dev/sda; fdisk /dev/sda", true},
		{"windows-guard", "Remove-Item -Recurse -Force a -WhatIf; Remove-Item -Recurse -Force b", true},
	}

	packs := map[string]pack{}
	for _, tc := range cases {
		if _, ok := packs[tc.pack]; !ok {
			packs[tc.pack] = loadPack(t, tc.pack)
		}
		fired := evaluate(t, packs[tc.pack], tc.command)
		if tc.fires && len(fired) == 0 {
			t.Errorf("%s: expected a rule to fire for %q, none did", tc.pack, tc.command)
		}
		if !tc.fires && len(fired) > 0 {
			t.Errorf("%s: expected no rule for %q, fired: %v", tc.pack, tc.command, fired)
		}
	}
}
