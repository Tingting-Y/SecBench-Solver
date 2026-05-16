"""Experience knowledge base for cross-instance learning.

Two knowledge bases accumulate over time:

  1. **Patch KB** — successful fixes: {vuln_type, repo, patch, property_report}
  2. **Mutation KB** — effective mutation strategies: {vuln_type, repo,
     which variants crashed, variant descriptions}

Both use 3-tier prioritised retrieval:
  Tier 1: same repo  + same vuln type   (strongest signal)
  Tier 2: other repo + same vuln type   (transferable patterns)
  Tier 3: BM25 similarity               (fallback)

Additionally, a static ``MUTATION_STRATEGY_HINTS`` table provides
domain-expert mutation guidance per vulnerability type (inspired by
SecVerifier's exploit-generation knowledge).
"""

from __future__ import annotations

import json
import logging
import os
import re
import string
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Vulnerability type extraction
# ---------------------------------------------------------------------------

# Sanitizer error patterns → canonical vuln type
_VULN_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("heap-buffer-overflow",    re.compile(r"heap-buffer-overflow")),
    ("stack-buffer-overflow",   re.compile(r"stack-buffer-overflow")),
    ("global-buffer-overflow",  re.compile(r"global-buffer-overflow")),
    ("use-after-free",          re.compile(r"use-after-free")),
    ("double-free",             re.compile(r"double-free")),
    ("null-pointer-dereference", re.compile(r"SEGV on unknown address.*0x0000000000|null pointer|null-dereference")),
    ("SEGV",                    re.compile(r"SEGV on unknown address")),
    ("use-of-uninitialized-value", re.compile(r"use-of-uninitialized-value")),
    ("memory-leak",             re.compile(r"detected memory leaks|LeakSanitizer")),
    ("stack-overflow",          re.compile(r"stack-overflow")),
    ("integer-overflow",        re.compile(r"integer overflow|runtime error:.*overflow")),
    ("undefined-behavior",      re.compile(r"UndefinedBehaviorSanitizer|runtime error:")),
]


def extract_vuln_type(sanitizer_output: str) -> str:
    """Extract canonical vulnerability type from sanitizer output.

    Returns the first matching type, or ``"unknown"`` if none match.
    Patterns are ordered from most specific to most general so that
    e.g. ``heap-buffer-overflow`` is preferred over a generic ``SEGV``.
    """
    for vuln_type, pattern in _VULN_PATTERNS:
        if pattern.search(sanitizer_output):
            return vuln_type
    return "unknown"


# ---------------------------------------------------------------------------
# Knowledge base I/O
# ---------------------------------------------------------------------------

# Each KB entry is a JSON line with these fields:
#   instance_id, repo, project_name, vuln_type,
#   sanitizer_report (truncated), bug_description,
#   patch, property_report

_KB_FILENAME = "experience_kb.jsonl"


def _kb_path(results_dir: str) -> str:
    return os.path.join(results_dir, _KB_FILENAME)


def save_experience(
    results_dir: str,
    instance_id: str,
    repo: str,
    project_name: str,
    sanitizer_report: str,
    bug_description: str,
    patch: str,
    property_report: str = "",
) -> None:
    """Append one successful-solve record to the knowledge base."""
    vuln_type = extract_vuln_type(sanitizer_report)
    entry = {
        "instance_id": instance_id,
        "repo": repo,
        "project_name": project_name,
        "vuln_type": vuln_type,
        "sanitizer_report": sanitizer_report[:2000],
        "bug_description": bug_description[:2000],
        "patch": patch[:4000],
        "property_report": property_report[:2000],
    }
    path = _kb_path(results_dir)
    os.makedirs(results_dir, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    logger.info(
        "Saved experience: %s (type=%s, repo=%s)",
        instance_id, vuln_type, repo,
    )


def load_kb(results_dir: str) -> list[dict]:
    """Load all KB entries, deduplicating by instance_id."""
    path = _kb_path(results_dir)
    if not os.path.exists(path):
        return []
    seen: set[str] = set()
    entries: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            iid = entry.get("instance_id", "")
            if iid not in seen:
                seen.add(iid)
                entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# Text preprocessing (for BM25)
# ---------------------------------------------------------------------------

_PUNCT_TABLE = str.maketrans("", "", string.punctuation)


def _tokenize(text: str) -> list[str]:
    """Lowercase, strip punctuation, split into tokens."""
    return text.lower().translate(_PUNCT_TABLE).split()


# ---------------------------------------------------------------------------
# BM25-Okapi (minimal self-contained implementation)
# ---------------------------------------------------------------------------

import math
from collections import Counter


class _BM25:
    """Minimal BM25-Okapi scorer — no numpy dependency."""

    def __init__(self, corpus: list[list[str]], k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.corpus_size = len(corpus)
        self.doc_lens = [len(d) for d in corpus]
        self.avgdl = sum(self.doc_lens) / max(self.corpus_size, 1)
        self.doc_freqs: list[Counter] = [Counter(d) for d in corpus]
        # IDF
        df: Counter = Counter()
        for d in corpus:
            df.update(set(d))
        self.idf: dict[str, float] = {}
        for term, freq in df.items():
            self.idf[term] = math.log(
                (self.corpus_size - freq + 0.5) / (freq + 0.5) + 1.0
            )

    def score(self, query: list[str]) -> list[float]:
        scores = [0.0] * self.corpus_size
        for q in query:
            q_idf = self.idf.get(q, 0.0)
            for i, (tf_map, dl) in enumerate(
                zip(self.doc_freqs, self.doc_lens)
            ):
                tf = tf_map.get(q, 0)
                denom = tf + self.k1 * (1 - self.b + self.b * dl / self.avgdl)
                scores[i] += q_idf * (tf * (self.k1 + 1)) / (denom + 1e-8)
        return scores


# ---------------------------------------------------------------------------
# 3-tier prioritized retrieval
# ---------------------------------------------------------------------------


def retrieve_experiences(
    results_dir: str,
    current_instance_id: str,
    repo: str,
    sanitizer_report: str,
    bug_description: str,
    max_examples: int = 2,
) -> list[dict]:
    """Retrieve relevant past experiences with 3-tier priority.

    Tier 1: same repo + same vuln type  (strongest signal)
    Tier 2: different repo + same vuln type  (transferable)
    Tier 3: BM25 over bug_description + sanitizer_report  (fallback)

    Returns up to *max_examples* entries, never including the current
    instance itself.
    """
    kb = load_kb(results_dir)
    if not kb:
        return []

    # Exclude self
    kb = [e for e in kb if e["instance_id"] != current_instance_id]
    if not kb:
        return []

    vuln_type = extract_vuln_type(sanitizer_report)

    # --- Tier 1: same repo + same vuln type ---
    tier1 = [
        e for e in kb
        if e.get("repo") == repo and e.get("vuln_type") == vuln_type
    ]

    # --- Tier 2: different repo + same vuln type ---
    tier2 = [
        e for e in kb
        if e.get("repo") != repo and e.get("vuln_type") == vuln_type
    ]

    # --- Tier 3: BM25 fallback (everything not already selected) ---
    selected_ids = {e["instance_id"] for e in tier1 + tier2}
    tier3_pool = [e for e in kb if e["instance_id"] not in selected_ids]

    tier3_ranked: list[dict] = []
    if tier3_pool:
        # Build BM25 index over combined text
        corpus = [
            _tokenize(e.get("bug_description", "") + " " + e.get("sanitizer_report", ""))
            for e in tier3_pool
        ]
        bm25 = _BM25(corpus)
        query = _tokenize(bug_description + " " + sanitizer_report)
        scores = bm25.score(query)
        ranked_idx = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        tier3_ranked = [tier3_pool[i] for i in ranked_idx]

    # Merge tiers respecting priority order, up to max_examples
    result: list[dict] = []
    for pool in (tier1, tier2, tier3_ranked):
        for entry in pool:
            if len(result) >= max_examples:
                break
            result.append(entry)
        if len(result) >= max_examples:
            break

    logger.info(
        "Experience retrieval for %s (type=%s): %d tier1, %d tier2, "
        "%d tier3 available; returning %d",
        current_instance_id, vuln_type,
        len(tier1), len(tier2), len(tier3_ranked), len(result),
    )
    return result


# ---------------------------------------------------------------------------
# Prompt formatting
# ---------------------------------------------------------------------------


def format_experience_prompt(experiences: list[dict]) -> str:
    """Format retrieved patch experiences as a few-shot section for Patcher.

    Returns an empty string if no experiences are available.
    """
    if not experiences:
        return ""

    lines = [
        "## Similar Vulnerability Fix Examples (from knowledge base)\n",
        "The following are patches that successfully fixed similar "
        "vulnerabilities. Use them as reference for your fix.\n",
    ]

    for i, exp in enumerate(experiences, 1):
        lines.append(f"### Example {i}: {exp.get('instance_id', '?')} "
                      f"[{exp.get('vuln_type', '?')}]")
        desc = exp.get("bug_description", "")
        if desc:
            lines.append(f"Bug: {desc[:500]}")
        san = exp.get("sanitizer_report", "")
        if san:
            lines.append(f"Sanitizer: {san[:300]}")
        patch = exp.get("patch", "")
        if patch:
            lines.append(f"```diff\n{patch[:2000]}\n```")
        prop = exp.get("property_report", "")
        if prop:
            lines.append(f"Property analysis: {prop[:500]}")
        lines.append("")

    return "\n".join(lines)


# ===================================================================
# Vulnerability-type-specific mutation strategy hints
# ===================================================================

# Domain-expert knowledge mapping vuln types to effective mutation
# strategies.  Drawn from common exploit-generation patterns (cf.
# SecVerifier's ExploiterAgent) and sanitizer semantics.

MUTATION_STRATEGY_HINTS: dict[str, str] = {
    "heap-buffer-overflow": (
        "Effective mutation strategies for heap-buffer-overflow:\n"
        "- Increase input size beyond expected buffer length\n"
        "- Vary length fields in structured input (headers, TLV records)\n"
        "- Use boundary values: exact buffer size, size+1, size-1, 0, max_uint\n"
        "- Change array/string lengths in nested structures\n"
        "- Truncate input to trigger short-read with stale length metadata"
    ),
    "stack-buffer-overflow": (
        "Effective mutation strategies for stack-buffer-overflow:\n"
        "- Create deeply nested structures (recursive parsing)\n"
        "- Provide very long strings for fixed-size stack buffers\n"
        "- Modify format strings or delimiter counts\n"
        "- Vary recursion depth in tree/graph structures"
    ),
    "global-buffer-overflow": (
        "Effective mutation strategies for global-buffer-overflow:\n"
        "- Similar to heap-buffer-overflow but target global/static arrays\n"
        "- Modify index or enum values used to access lookup tables\n"
        "- Vary encoding values that map to table indices"
    ),
    "use-after-free": (
        "Effective mutation strategies for use-after-free:\n"
        "- Trigger object destruction then re-reference (double close, "
        "re-parse after free)\n"
        "- Interleave allocation/deallocation sequences\n"
        "- Use callbacks or error paths that free objects prematurely\n"
        "- Trigger exception/error during object lifetime"
    ),
    "double-free": (
        "Effective mutation strategies for double-free:\n"
        "- Trigger error paths that call free() on already-freed memory\n"
        "- Duplicate resource handles (file descriptors, pointers)\n"
        "- Cause cleanup code to run twice (exception + normal path)"
    ),
    "null-pointer-dereference": (
        "Effective mutation strategies for null-pointer-dereference:\n"
        "- Remove or empty optional fields that code assumes non-null\n"
        "- Provide empty containers (empty arrays, empty strings, zero-length)\n"
        "- Trigger error paths where initialization is skipped\n"
        "- Vary presence/absence of optional data sections"
    ),
    "SEGV": (
        "Effective mutation strategies for SEGV:\n"
        "- Corrupt pointer-bearing fields in structured data\n"
        "- Provide invalid offsets or sizes in binary formats\n"
        "- Trigger uninitialized pointer access via partial input\n"
        "- Combine null-pointer and buffer-overflow strategies"
    ),
    "use-of-uninitialized-value": (
        "Effective mutation strategies for uninitialized value use:\n"
        "- Truncate input so fields are partially read\n"
        "- Skip initialization sequences via malformed headers\n"
        "- Provide minimal/empty input for complex structures\n"
        "- Corrupt type tags to mislead initialization dispatch"
    ),
    "integer-overflow": (
        "Effective mutation strategies for integer-overflow:\n"
        "- Use extreme numeric values: INT_MAX, INT_MIN, 0, -1, UINT_MAX\n"
        "- Multiply large dimensions (width*height overflow)\n"
        "- Set count/size fields to values near type boundaries\n"
        "- Mix signed/unsigned boundary values"
    ),
    "memory-leak": (
        "Effective mutation strategies for memory-leak:\n"
        "- Trigger early-return error paths that skip cleanup\n"
        "- Provide many iterations of allocation-heavy operations\n"
        "- Cause exceptions during resource-owning operations"
    ),
    "undefined-behavior": (
        "Effective mutation strategies for undefined behavior:\n"
        "- Trigger division by zero with zero-valued fields\n"
        "- Cause shift amounts >= type width\n"
        "- Provide inputs that cause signed overflow in arithmetic\n"
        "- Use extreme enum/flag values outside expected range"
    ),
}


def get_mutation_strategy_hint(vuln_type: str) -> str:
    """Return domain-expert mutation strategy for a vulnerability type.

    Returns an empty string for unknown types.
    """
    return MUTATION_STRATEGY_HINTS.get(vuln_type, "")


# ===================================================================
# Mutation experience KB
# ===================================================================

_MUTATION_KB_FILENAME = "mutation_experience_kb.jsonl"


def _mutation_kb_path(results_dir: str) -> str:
    return os.path.join(results_dir, _MUTATION_KB_FILENAME)


def save_mutation_experience(
    results_dir: str,
    instance_id: str,
    repo: str,
    project_name: str,
    vuln_type: str,
    crash_reports: list[dict],
    sanitizer_report: str = "",
    bug_description: str = "",
    mutation_strategy_summary: str = "",
) -> None:
    """Append one mutation-experience record to the mutation KB.

    Stores semantic-level mutation strategy information for cross-instance
    learning, including:
    - What mutation strategy was used and why
    - Boundary conditions discovered from crash/non-crash differential
    - Key characteristics of crashing vs safe inputs
    """
    # Build compact variant summaries with semantic info
    variant_summaries: list[dict] = []
    for r in crash_reports:
        variant_summaries.append({
            "variant": r.get("variant", ""),
            "crashed": r.get("crashed", False),
            "vuln_type": r.get("vuln_type", "unknown"),
            "mutation_how": r.get("mutation_how", ""),
            "output_snippet": (r.get("output", ""))[:500],
        })

    num_crashed = sum(1 for r in crash_reports if r.get("crashed"))
    num_non_crashed = sum(1 for r in crash_reports if not r.get("crashed"))

    # Extract crash vs safe input characteristics (compact, no raw commands)
    crash_characteristics = []
    safe_characteristics = []
    for r in crash_reports:
        variant = r.get("variant", "?")
        vtype = r.get("vuln_type", "unknown")
        snippet = (r.get("output", "") or "")[:200].strip()
        if r.get("crashed"):
            crash_characteristics.append(f"{variant} [{vtype}]: {snippet}")
        else:
            safe_characteristics.append(f"{variant} [{vtype}]: {snippet}")

    entry = {
        "entry_id": f"{instance_id}#mut",
        "instance_id": instance_id,
        "repo": repo,
        "project_name": project_name,
        "vuln_type": vuln_type,
        "sanitizer_report": sanitizer_report[:1500],
        "bug_description": bug_description[:1500],
        "num_variants": len(crash_reports),
        "num_crashed": num_crashed,
        "num_non_crashed": num_non_crashed,
        # Semantic-level strategy information
        "mutation_strategy_summary": mutation_strategy_summary[:2000],
        "crash_input_characteristics": crash_characteristics[:5],
        "safe_input_characteristics": safe_characteristics[:5],
        # Compact variant details
        "variants": variant_summaries[:20],
    }
    path = _mutation_kb_path(results_dir)
    os.makedirs(results_dir, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    logger.info(
        "Saved mutation experience: %s (type=%s, crash=%d, no-crash=%d, total=%d)",
        instance_id, vuln_type,
        entry["num_crashed"], entry["num_non_crashed"], entry["num_variants"],
    )


def _load_mutation_kb(results_dir: str) -> list[dict]:
    """Load mutation KB entries, deduplicating by stable entry key."""
    path = _mutation_kb_path(results_dir)
    if not os.path.exists(path):
        return []
    seen: set[str] = set()
    entries: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            key = entry.get("entry_id") or entry.get("instance_id", "")
            if key not in seen:
                seen.add(key)
                entries.append(entry)
    return entries


def retrieve_mutation_experiences(
    results_dir: str,
    current_instance_id: str,
    repo: str,
    sanitizer_report: str,
    bug_description: str,
    max_examples: int = 2,
) -> list[dict]:
    """Retrieve relevant mutation experiences with 3-tier priority.

    Same priority scheme as patch experience retrieval.
    Only returns entries where at least 1 variant crashed.
    """
    kb = _load_mutation_kb(results_dir)
    if not kb:
        return []

    # Exclude self first.
    kb = [e for e in kb if e.get("instance_id") != current_instance_id]
    if not kb:
        return []

    # Prefer examples that have BOTH crash and non-crash variants.
    preferred = [
        e for e in kb
        if e.get("num_crashed", 0) > 0 and e.get("num_non_crashed", 0) > 0
    ]
    if preferred:
        kb = preferred
    else:
        kb = [e for e in kb if e.get("num_crashed", 0) > 0]
        if not kb:
            return []

    vuln_type = extract_vuln_type(sanitizer_report)

    tier1 = [e for e in kb if e.get("repo") == repo and e.get("vuln_type") == vuln_type]
    tier2 = [e for e in kb if e.get("repo") != repo and e.get("vuln_type") == vuln_type]

    selected_ids = {e["instance_id"] for e in tier1 + tier2}
    tier3_pool = [e for e in kb if e["instance_id"] not in selected_ids]

    tier3_ranked: list[dict] = []
    if tier3_pool:
        corpus = [
            _tokenize(e.get("bug_description", "") + " " + e.get("sanitizer_report", ""))
            for e in tier3_pool
        ]
        bm25 = _BM25(corpus)
        query = _tokenize(bug_description + " " + sanitizer_report)
        scores = bm25.score(query)
        ranked_idx = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        tier3_ranked = [tier3_pool[i] for i in ranked_idx]

    result: list[dict] = []
    for pool in (tier1, tier2, tier3_ranked):
        for entry in pool:
            if len(result) >= max_examples:
                break
            result.append(entry)
        if len(result) >= max_examples:
            break

    logger.info(
        "Mutation experience retrieval for %s (type=%s): returning %d",
        current_instance_id, vuln_type, len(result),
    )
    return result


def format_mutation_prompt(
    vuln_type: str,
    mutation_experiences: list[dict],
) -> str:
    """Build a mutation guidance section for the Mutator prompt.

    Combines:
      1. Static domain-expert hints for the vulnerability type
      2. Retrieved past mutation experiences with semantic strategy info
    """
    parts: list[str] = []

    # Static strategy hints
    hint = get_mutation_strategy_hint(vuln_type)
    if hint:
        parts.append(f"## Mutation Strategy Guidance (for {vuln_type})\n")
        parts.append(hint)
        parts.append("")

    # Retrieved mutation experiences
    if mutation_experiences:
        parts.append("## Mutation Examples from Similar Vulnerabilities\n")
        parts.append(
            "The following mutation approaches worked on similar "
            "vulnerabilities. Use them as inspiration.\n"
        )
        for i, exp in enumerate(mutation_experiences, 1):
            parts.append(
                f"### Mutation Example {i}: {exp.get('instance_id', '?')} "
                f"[{exp.get('vuln_type', '?')}]"
            )
            parts.append(
                f"Result: {exp.get('num_crashed', 0)}/{exp.get('num_variants', 0)} "
                f"crashed, {exp.get('num_non_crashed', 0)} did not crash."
            )

            # Semantic strategy summary (the key improvement)
            strategy = exp.get("mutation_strategy_summary", "")
            if strategy:
                parts.append(f"Strategy: {strategy[:800]}")

            # Crash vs safe input characteristics
            crash_chars = exp.get("crash_input_characteristics", [])
            safe_chars = exp.get("safe_input_characteristics", [])
            if crash_chars:
                parts.append("Crashing input characteristics:")
                for c in crash_chars[:3]:
                    parts.append(f"  - {c}")
            if safe_chars:
                parts.append("Safe (non-crashing) input characteristics:")
                for c in safe_chars[:3]:
                    parts.append(f"  - {c}")

            parts.append("")

    return "\n".join(parts)
