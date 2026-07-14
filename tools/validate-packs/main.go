// Command validate-packs checks every pack in packs/ against the library
// schema and verifies all regex patterns compile under Go RE2 (the engine
// tracelet uses at evaluation time). It also cross-checks index.json.
//
// Usage: go run ./tools/validate-packs [library-root]
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var validActions = map[string]bool{
	"block": true, "warn": true, "log": true, "approve": true,
	"justify": true, "request_access": true, "redact": true,
}

var validRuleTypes = map[string]bool{
	"command_filter": true, "secret_detection": true, "pii_redact": true,
	"image_pii": true, "file_access": true, "content_filter": true,
	"mcp_filter": true, "opa": true,
}

var validSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true,
}

var validFailModes = map[string]bool{"closed": true, "open": true}

type rule struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Action      string          `json:"action"`
	FailMode    string          `json:"fail_mode"`
	Severity    string          `json:"severity"`
	Priority    int             `json:"priority"`
	RuleType    string          `json:"rule_type"`
	RuleConfig  json.RawMessage `json:"rule_config"`
}

type pack struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Rules       []rule `json:"rules"`
}

type indexEntry struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	RuleCount int    `json:"rule_count"`
}

type indexFile struct {
	Packs []indexEntry `json:"packs"`
}

type patternConfig struct {
	BlockedPatterns []string `json:"blocked_patterns"`
	AllowedPatterns []string `json:"allowed_patterns"`
	Patterns        []string `json:"patterns"`
}

var problems int

func fail(format string, args ...any) {
	problems++
	fmt.Printf("FAIL  "+format+"\n", args...)
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	files, err := filepath.Glob(filepath.Join(root, "packs", "*.json"))
	if err != nil || len(files) == 0 {
		fmt.Println("FAIL  no pack files found under packs/")
		os.Exit(1)
	}

	packCounts := map[string]int{}
	packVersions := map[string]string{}

	for _, f := range files {
		base := filepath.Base(f)
		data, err := os.ReadFile(f)
		if err != nil {
			fail("%s: %v", base, err)
			continue
		}
		var p pack
		if err := json.Unmarshal(data, &p); err != nil {
			fail("%s: invalid JSON: %v", base, err)
			continue
		}
		if p.ID != strings.TrimSuffix(base, ".json") {
			fail("%s: id %q does not match filename", base, p.ID)
		}
		if p.Name == "" || p.Category == "" || p.Description == "" || p.Version == "" {
			fail("%s: missing name/category/description/version", base)
		}
		if len(p.Rules) == 0 {
			fail("%s: no rules", base)
		}
		packCounts[p.ID] = len(p.Rules)
		packVersions[p.ID] = p.Version

		seenNames := map[string]bool{}
		for i, r := range p.Rules {
			where := fmt.Sprintf("%s rule[%d] %q", base, i, r.Name)
			if r.Name == "" || r.Description == "" {
				fail("%s: missing name or description", where)
			}
			if seenNames[r.Name] {
				fail("%s: duplicate rule name", where)
			}
			seenNames[r.Name] = true
			if !validActions[r.Action] {
				fail("%s: invalid action %q", where, r.Action)
			}
			if !validRuleTypes[r.RuleType] {
				fail("%s: invalid rule_type %q", where, r.RuleType)
			}
			if !validSeverities[r.Severity] {
				fail("%s: invalid severity %q", where, r.Severity)
			}
			if !validFailModes[r.FailMode] {
				fail("%s: invalid fail_mode %q", where, r.FailMode)
			}
			var pc patternConfig
			if err := json.Unmarshal(r.RuleConfig, &pc); err != nil {
				fail("%s: rule_config: %v", where, err)
				continue
			}
			for _, group := range [][]string{pc.BlockedPatterns, pc.AllowedPatterns, pc.Patterns} {
				for _, rx := range group {
					if _, err := regexp.Compile(rx); err != nil {
						fail("%s: pattern does not compile under RE2: %v", where, err)
					}
				}
			}
		}
	}

	// index.json cross-check
	idxData, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		fail("index.json: %v", err)
	} else {
		var idx indexFile
		if err := json.Unmarshal(idxData, &idx); err != nil {
			fail("index.json: invalid JSON: %v", err)
		} else {
			indexed := map[string]bool{}
			for _, e := range idx.Packs {
				indexed[e.ID] = true
				count, ok := packCounts[e.ID]
				if !ok {
					fail("index.json: pack %q has no packs/%s.json", e.ID, e.ID)
					continue
				}
				if e.RuleCount != count {
					fail("index.json: pack %q rule_count=%d but file has %d rules", e.ID, e.RuleCount, count)
				}
				if e.Version != packVersions[e.ID] {
					fail("index.json: pack %q version %q != file version %q", e.ID, e.Version, packVersions[e.ID])
				}
			}
			for id := range packCounts {
				if !indexed[id] {
					fail("packs/%s.json is not listed in index.json", id)
				}
			}
		}
	}

	if problems > 0 {
		fmt.Printf("\n%d problem(s)\n", problems)
		os.Exit(1)
	}
	fmt.Printf("OK  %d packs validated\n", len(files))
}
