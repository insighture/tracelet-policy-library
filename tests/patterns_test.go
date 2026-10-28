// Package tests checks every policy pack's command_filter patterns.
//
// The Tracelet agent matches each blocked pattern against the whole shell
// line, so a bare `.*` runs across `&&`, `;` and `||` into the next chained
// command: `git push origin feat && gh pr create --base main` then reads as a
// push to main. These tests compile every pattern, reject unbounded wildcards,
// and run the must_block / must_not_block cases in cases.json.
package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type pack struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Rules   []struct {
		Name       string `json:"name"`
		RuleType   string `json:"rule_type"`
		RuleConfig struct {
			BlockedPatterns []string `json:"blocked_patterns"`
		} `json:"rule_config"`
	} `json:"rules"`
}

type index struct {
	Packs []struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	} `json:"packs"`
}

type ruleCases struct {
	MustBlock    []string `json:"must_block"`
	MustNotBlock []string `json:"must_not_block"`
}

func loadPacks(t *testing.T) map[string]pack {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "packs", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no packs found: %v", err)
	}
	out := map[string]pack{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var p pack
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		out[p.ID] = p
	}
	return out
}

// unboundedWildcard reports a `.*`, `.+`, `.*?` or `.+?` that sits outside a
// character class and is not an escaped dot.
func unboundedWildcard(p string) bool {
	inClass := false
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == '\\':
			i++ // skip the escaped character
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
			// a ']' right after '[' or '[^' is a literal
			if i+1 < len(p) && p[i+1] == '^' {
				i++
			}
			if i+1 < len(p) && p[i+1] == ']' {
				i++
			}
		case c == '.' && i+1 < len(p) && (p[i+1] == '*' || p[i+1] == '+'):
			return true
		}
	}
	return false
}

func TestPatternsCompile(t *testing.T) {
	for id, p := range loadPacks(t) {
		for _, r := range p.Rules {
			for _, pat := range r.RuleConfig.BlockedPatterns {
				if _, err := regexp.Compile(pat); err != nil {
					t.Errorf("%s / %s: invalid RE2 %q: %v", id, r.Name, pat, err)
				}
			}
		}
	}
}

func TestNoUnboundedWildcards(t *testing.T) {
	for id, p := range loadPacks(t) {
		for _, r := range p.Rules {
			if r.RuleType != "command_filter" {
				continue
			}
			for _, pat := range r.RuleConfig.BlockedPatterns {
				if unboundedWildcard(pat) {
					t.Errorf("%s / %s: %q uses an unbounded wildcard; use [^;&|\\n]* so the match stays inside one command", id, r.Name, pat)
				}
			}
		}
	}
}

func TestIndexVersionsMatchPacks(t *testing.T) {
	packs := loadPacks(t)
	raw, err := os.ReadFile(filepath.Join("..", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx index
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	for _, e := range idx.Packs {
		p, ok := packs[e.ID]
		if !ok {
			t.Errorf("index lists %s but packs/%s.json is missing", e.ID, e.ID)
			continue
		}
		if p.Version != e.Version {
			t.Errorf("%s: index version %s, pack version %s", e.ID, e.Version, p.Version)
		}
	}
}

// matches mirrors the agent: a rule fires when any of its blocked patterns
// matches the original or the lowercased command.
func matches(pats []*regexp.Regexp, cmd string) bool {
	for _, re := range pats {
		if re.MatchString(cmd) || re.MatchString(strings.ToLower(cmd)) {
			return true
		}
	}
	return false
}

func TestCases(t *testing.T) {
	packs := loadPacks(t)
	raw, err := os.ReadFile("cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string]map[string]ruleCases
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases.json: %v", err)
	}
	for packID, rules := range cases {
		p, ok := packs[packID]
		if !ok {
			t.Errorf("cases.json: unknown pack %s", packID)
			continue
		}
		for ruleName, rc := range rules {
			var pats []*regexp.Regexp
			for _, r := range p.Rules {
				if r.Name == ruleName {
					for _, s := range r.RuleConfig.BlockedPatterns {
						pats = append(pats, regexp.MustCompile(s))
					}
				}
			}
			if len(pats) == 0 {
				t.Errorf("cases.json: %s has no rule %q with blocked patterns", packID, ruleName)
				continue
			}
			for _, c := range rc.MustBlock {
				if !matches(pats, c) {
					t.Errorf("%s / %s: should block %q", packID, ruleName, c)
				}
			}
			for _, c := range rc.MustNotBlock {
				if matches(pats, c) {
					t.Errorf("%s / %s: should NOT block %q", packID, ruleName, c)
				}
			}
		}
	}
}
