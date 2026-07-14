#!/usr/bin/env python3
"""Extract destructive/safe patterns from destructive_command_guard (dcg) Rust sources.

dcg embeds its rule data in Rust macro invocations:

    destructive_pattern!("name", r"regex", "reason", Critical, "explanation", SUGGESTIONS)
    safe_pattern!("name", r"regex")

This script parses every file under <dcg-repo>/src/packs/, resolves suggestion
constants, and emits one JSON corpus with all packs and their patterns.

Usage:
    python extract.py <dcg-repo-path> <output-corpus.json>
"""

import json
import re
import sys
from pathlib import Path

SEVERITIES = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}


def strip_comments(src: str) -> str:
    """Remove // and /* */ comments while preserving string literals."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        # raw string literal r"..." / r#"..."#
        if c == "r" and i + 1 < n and src[i + 1] in '#"' and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            j = i + 1
            hashes = 0
            while j < n and src[j] == "#":
                hashes += 1
                j += 1
            if j < n and src[j] == '"':
                closer = '"' + "#" * hashes
                end = src.find(closer, j + 1)
                if end != -1:
                    out.append(src[i : end + len(closer)])
                    i = end + len(closer)
                    continue
        if c == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    break
                j += 1
            out.append(src[i : j + 1])
            i = j + 1
            continue
        if c == "'" and i + 2 < n and (src[i + 1] == "\\" or src[i + 2] == "'"):
            # char literal (best effort; lifetimes like 'static fall through)
            j = i + 1
            if src[j] == "\\":
                j += 1
            j += 1
            if j < n and src[j] == "'":
                out.append(src[i : j + 1])
                i = j + 1
                continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            i = n if j == -1 else j
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def decode_string_literal(tok: str) -> str:
    """Decode a Rust string literal token (normal, raw, or raw-with-hashes)."""
    tok = tok.strip()
    if tok.startswith("r"):
        body = tok[1:]
        hashes = 0
        while body.startswith("#"):
            hashes += 1
            body = body[1:]
        assert body.startswith('"') and body.endswith('"' + "#" * hashes), tok[:60]
        return body[1 : len(body) - 1 - hashes]
    assert tok.startswith('"') and tok.endswith('"'), tok[:60]
    body = tok[1:-1]
    out = []
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt == "\n":
            # line continuation: skip newline and following whitespace
            i += 2
            while i < n and body[i] in " \t":
                i += 1
            continue
        mapping = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "'": "'", "0": "\0"}
        if nxt in mapping:
            out.append(mapping[nxt])
            i += 2
        elif nxt == "u":
            m = re.match(r"u\{([0-9a-fA-F]+)\}", body[i + 1 :])
            assert m, body[i : i + 12]
            out.append(chr(int(m.group(1), 16)))
            i += 1 + m.end()
        elif nxt == "x":
            out.append(chr(int(body[i + 2 : i + 4], 16)))
            i += 4
        else:
            raise ValueError(f"unknown escape \\{nxt}")
    return "".join(out)


def find_macro_calls(src: str, macro: str):
    """Yield the raw argument text of every `macro!( ... )` invocation."""
    needle = macro + "!("
    start = 0
    while True:
        idx = src.find(needle, start)
        if idx == -1:
            return
        # skip if part of a longer identifier (e.g. doc text)
        if idx > 0 and (src[idx - 1].isalnum() or src[idx - 1] == "_"):
            start = idx + 1
            continue
        i = idx + len(needle)
        depth = 1
        args_start = i
        n = len(src)
        while i < n and depth > 0:
            c = src[i]
            if c == "r" and i + 1 < n and src[i + 1] in '#"' and not (src[i - 1].isalnum() or src[i - 1] == "_"):
                j = i + 1
                hashes = 0
                while j < n and src[j] == "#":
                    hashes += 1
                    j += 1
                if j < n and src[j] == '"':
                    closer = '"' + "#" * hashes
                    end = src.find(closer, j + 1)
                    i = end + len(closer)
                    continue
            if c == '"':
                j = i + 1
                while j < n:
                    if src[j] == "\\":
                        j += 2
                        continue
                    if src[j] == '"':
                        break
                    j += 1
                i = j + 1
                continue
            if c in "([{":
                depth += 1 if c == "(" else 0
            if c == "(":
                pass
            elif c == ")":
                depth -= 1
            i += 1
        yield src[args_start : i - 1]
        start = i


def split_top_level_args(argtext: str):
    """Split macro argument text on top-level commas, respecting strings/brackets."""
    args = []
    buf = []
    depth = 0
    i, n = 0, len(argtext)
    while i < n:
        c = argtext[i]
        if c == "r" and i + 1 < n and argtext[i + 1] in '#"' and (i == 0 or not (argtext[i - 1].isalnum() or argtext[i - 1] == "_")):
            j = i + 1
            hashes = 0
            while j < n and argtext[j] == "#":
                hashes += 1
                j += 1
            if j < n and argtext[j] == '"':
                closer = '"' + "#" * hashes
                end = argtext.find(closer, j + 1)
                buf.append(argtext[i : end + len(closer)])
                i = end + len(closer)
                continue
        if c == '"':
            j = i + 1
            while j < n:
                if argtext[j] == "\\":
                    j += 2
                    continue
                if argtext[j] == '"':
                    break
                j += 1
            buf.append(argtext[i : j + 1])
            i = j + 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
        else:
            buf.append(c)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        args.append(tail)
    return args


def parse_suggestion_consts(src: str):
    """Map SUGGESTION const name -> list of {command, note}."""
    consts = {}
    for m in re.finditer(r"const\s+([A-Z0-9_]+)\s*:\s*&\[PatternSuggestion\]\s*=\s*&\[", src):
        name = m.group(1)
        # capture the balanced [...] body
        i = m.end() - 1  # at '['
        depth = 0
        n = len(src)
        j = i
        while j < n:
            c = src[j]
            if c == '"':
                k = j + 1
                while k < n:
                    if src[k] == "\\":
                        k += 2
                        continue
                    if src[k] == '"':
                        break
                    k += 1
                j = k + 1
                continue
            if c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body = src[i + 1 : j]
        consts[name] = parse_suggestion_body(body)
    return consts


def parse_suggestion_body(body: str):
    out = []
    for call in find_macro_calls("x" + body.replace("PatternSuggestion::new(", "patsug!("), "patsug"):
        args = split_top_level_args(call)
        if len(args) >= 2:
            out.append({"command": decode_string_literal(args[0]), "note": decode_string_literal(args[1])})
    return out


def is_string_literal(tok: str) -> bool:
    tok = tok.strip()
    return tok.startswith('"') or tok.startswith('r"') or tok.startswith('r#')


def parse_file(path: Path, rel: str):
    src = strip_comments(path.read_text(encoding="utf-8"))
    # drop test modules (patterns constructed in tests are not rule data)
    cut = src.find("#[cfg(test)]")
    if cut != -1:
        src = src[:cut]

    suggestion_consts = parse_suggestion_consts(src)

    pack_ids = re.findall(r'id:\s*"([^"]+)"\s*\.to_string\(\)', src)
    pack_ids += re.findall(r'Pack::new\(\s*"([^"]+)"\s*\.to_string\(\)', src)

    destructive = []
    for raw in find_macro_calls(src, "destructive_pattern"):
        args = split_top_level_args(raw)
        entry = {"name": None, "regex": None, "reason": None, "severity": "high",
                 "explanation": None, "suggestions": [], "file": rel}
        if len(args) == 2:
            entry["regex"] = decode_string_literal(args[0])
            entry["reason"] = decode_string_literal(args[1])
        else:
            entry["name"] = decode_string_literal(args[0])
            entry["regex"] = decode_string_literal(args[1])
            entry["reason"] = decode_string_literal(args[2])
            if len(args) >= 4:
                sev = args[3].strip()
                if sev not in SEVERITIES:
                    raise ValueError(f"{rel}: unknown severity {sev!r} in {args[0]}")
                entry["severity"] = SEVERITIES[sev]
            if len(args) >= 5:
                entry["explanation"] = decode_string_literal(args[4])
            if len(args) >= 6:
                sugg = args[5].strip()
                if sugg.startswith("&["):
                    entry["suggestions"] = parse_suggestion_body(sugg[2:-1])
                elif sugg in suggestion_consts:
                    entry["suggestions"] = suggestion_consts[sugg]
                elif sugg != "&[]":
                    entry["suggestions"] = []  # unresolvable cross-file const; rare
        destructive.append(entry)

    safe = []
    for raw in find_macro_calls(src, "safe_pattern"):
        args = split_top_level_args(raw)
        if len(args) == 2 and is_string_literal(args[0]) and is_string_literal(args[1]):
            safe.append({"name": decode_string_literal(args[0]),
                         "regex": decode_string_literal(args[1]), "file": rel})

    return pack_ids, destructive, safe


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    dcg_root = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    packs_dir = dcg_root / "src" / "packs"
    if not packs_dir.is_dir():
        print(f"error: {packs_dir} not found", file=sys.stderr)
        sys.exit(1)

    files = {}
    for path in sorted(packs_dir.rglob("*.rs")):
        rel = path.relative_to(packs_dir).as_posix()
        if rel in ("mod.rs", "external.rs", "regex_engine.rs", "test_helpers.rs", "test_template.rs"):
            continue
        pack_ids, destructive, safe = parse_file(path, rel)
        if not destructive and not safe:
            continue
        files[rel] = {
            "pack_ids": pack_ids,
            "destructive": destructive,
            "safe": safe,
        }

    total_d = sum(len(f["destructive"]) for f in files.values())
    total_s = sum(len(f["safe"]) for f in files.values())
    unnamed = sum(1 for f in files.values() for p in f["destructive"] if not p["name"])
    corpus = {"source": "destructive_command_guard", "files": files,
              "totals": {"destructive": total_d, "safe": total_s, "unnamed": unnamed}}
    out_path.write_text(json.dumps(corpus, indent=2), encoding="utf-8")
    print(f"files: {len(files)}  destructive: {total_d}  safe: {total_s}  unnamed: {unnamed}")


if __name__ == "__main__":
    main()
