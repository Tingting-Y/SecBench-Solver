"""Adversarial differential analysis pipeline for SEC-bench solver.

Architecture:
  Stage 0: Setup (start container, build, verify original PoC crashes)
  Stage 1: Adversarial Loop (Mutate -> Analyze -> Patch -> Verify -> feedback)
           The Analyze stage discovers violated safety properties from crash
           differentials.  Properties guide subsequent Patch and Mutate stages.
           Saves every patch that passes the original PoC as a candidate.
  Stage 2: Selection (if multiple candidates, Selector picks the most robust one)

The Patcher agent edits source files directly via tools.  The pipeline
extracts the resulting patch with ``git --no-pager diff`` — the LLM never
generates unified-diff text itself.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.messages import ToolCallRequestEvent
from autogen_ext.models.openai import OpenAIChatCompletionClient

from agents import create_analyzer, create_model_client, create_mutator, create_patcher, create_selector
from config import (
    ABLATION_SKIP_ANALYZER,
    ABLATION_SKIP_MUTATOR,
    ABLATION_SKIP_MUTATION_EXP,
    ABLATION_SKIP_PATCHER_EXP,
    MAX_ADVERSARIAL_ROUNDS,
    MAX_MUTATION_RETRIES,
    MAX_MUTATION_VARIANTS,
    MAX_PATCHER_RETRIES,
    PATCHES_PER_ROUND,
    PATCHER_TEMPERATURE,
)
from experience import (
    extract_vuln_type,
    format_experience_prompt,
    format_mutation_prompt,
    retrieve_experiences,
    retrieve_mutation_experiences,
    save_experience,
    save_mutation_experience,
)
from docker_tools import (
    apply_patch,
    build_project,
    copy_from_container,
    exec_cmd,
    get_image_name,
    read_file,
    reset_source,
    run_custom_repro,
    run_repro,
    start_container,
    start_patcher_containers,
    stop_container,
    stop_containers,
    write_file,
)
from repro_parser import ReproCommand, parse_repro_command
from trajectory import append_agent_trajectory, init_trajectory, summarize_token_usage

logger = logging.getLogger(__name__)

# Maximum retries for transient API errors (connection reset, timeout, etc.)
_API_RETRY_MAX = 3
_API_RETRY_DELAY = 30  # seconds


async def _run_with_retry(agent, task: str, retries: int = _API_RETRY_MAX):
    """Run an agent with automatic retry on transient API errors."""
    for attempt in range(1, retries + 1):
        try:
            return await agent.run(task=task)
        except (Exception,) as exc:
            exc_name = type(exc).__name__
            # Only retry on connection / timeout / server errors
            retriable = any(kw in exc_name for kw in ("Connection", "Timeout", "Server")) or \
                         any(kw in str(exc) for kw in ("Connection", "disconnected", "timed out", "502", "503", "529"))
            if retriable and attempt < retries:
                logger.warning(
                    "API error (%s), retrying agent %s in %ds (attempt %d/%d): %s",
                    exc_name, agent.name, _API_RETRY_DELAY, attempt, retries, str(exc)[:200],
                )
                await asyncio.sleep(_API_RETRY_DELAY)
                continue
            raise


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _has_sanitizer_error(output: str) -> bool:
    """Check if output contains ANY sanitizer error indicator."""
    indicators = [
        "ERROR: AddressSanitizer",
        "ERROR: MemorySanitizer",
        "ERROR: UndefinedBehaviorSanitizer",
        "ERROR: LeakSanitizer",
        "ERROR: ThreadSanitizer",
        "SUMMARY: AddressSanitizer",
        "SUMMARY: MemorySanitizer",
        "SUMMARY: UndefinedBehaviorSanitizer",
        "runtime error:",
    ]
    return any(ind in output for ind in indicators)


def _matches_vuln_type(output: str, orig_vuln_type: str) -> bool:
    """Check if *output* triggers the SAME vulnerability type as the original PoC.

    A variant is considered a "same-bug crash" only when its sanitizer output
    maps to the same canonical vulnerability type (via ``extract_vuln_type``).
    This prevents counting unrelated sanitizer errors as valid crash
    reproductions, which would confuse the differential analysis.

    Falls back to ``_has_sanitizer_error`` when the original vuln type is
    ``"unknown"`` (no pattern matched for the original PoC).
    """
    if orig_vuln_type == "unknown":
        # Cannot narrow — accept any sanitizer error
        return _has_sanitizer_error(output)
    variant_type = extract_vuln_type(output)
    return variant_type == orig_vuln_type


def _truncate(text: str, max_len: int = 3000) -> str:
    """Truncate text for prompt inclusion, keeping head and tail."""
    if len(text) <= max_len:
        return text
    half = max_len // 2
    return text[:half] + "\n... [truncated] ...\n" + text[-half:]


def _get_extension(path: str) -> str:
    """Get file extension from a path."""
    import posixpath
    _, ext = posixpath.splitext(path)
    return ext if ext else ""


def _extract_selected_index(selector_output: str) -> int | None:
    """Extract the selected candidate number from Selector output."""
    match = re.search(r'SELECTED:\s*(\d+)', selector_output)
    if match:
        return int(match.group(1))
    return None


def _content_to_str(content) -> str:
    """Normalise an AutoGen message .content to a plain string.

    AutoGen may return content as a ``str`` or as a ``list`` of content
    blocks (dicts with ``"text"`` keys, or other types).  This helper
    handles both cases and preserves newlines.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                parts.append(item.get("text", ""))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(content) if content else ""


def _safe_instance_id(instance_id: str) -> str:
    """Sanitize instance_id for host filesystem paths."""
    return instance_id.replace("/", "_").replace("\\", "_")


def _extract_bash_command(arguments) -> str:
    """Extract the ``command`` argument from a tool call payload."""
    if isinstance(arguments, dict):
        cmd = arguments.get("command")
        return cmd if isinstance(cmd, str) else ""
    if isinstance(arguments, str):
        try:
            parsed = json.loads(arguments)
            if isinstance(parsed, dict):
                cmd = parsed.get("command")
                return cmd if isinstance(cmd, str) else ""
        except json.JSONDecodeError:
            return ""
    return ""


def _build_mutation_strategy_summary(
    crash_reports: list[dict],
    mutation_attempt_records: list[dict],
) -> str:
    """Build a semantic-level mutation strategy summary from available data.

    Extracts what mutation strategies were used and what the crash/non-crash
    differential reveals about the vulnerability boundary, without an extra
    LLM call.
    """
    parts: list[str] = []

    # Summarise from Mutator's assistant_summary (its own reasoning)
    for rec in mutation_attempt_records:
        trace = rec.get("mutation_trace", {})
        if isinstance(trace, dict):
            summary = trace.get("assistant_summary", "")
            if summary:
                parts.append(summary[:800])
                break  # Use the first non-empty summary

    # Extract differential insight from crash vs non-crash
    crashed = [r for r in crash_reports if r.get("crashed")]
    safe = [r for r in crash_reports if not r.get("crashed")]

    if crashed or safe:
        parts.append(
            f"Differential: {len(crashed)} inputs crashed, "
            f"{len(safe)} did not."
        )
        # Summarise variant-level info compactly (name + vuln_type only)
        for r in crashed[:3]:
            parts.append(f"  Crash: {r.get('variant', '?')} [{r.get('vuln_type', '?')}]")
        for r in safe[:3]:
            parts.append(f"  Safe:  {r.get('variant', '?')} [{r.get('vuln_type', '?')}]")

    return "\n".join(parts)[:2000]


def _extract_mutator_trace(messages) -> dict:
    """Extract mutator operations from trajectory messages.

    Returns a compact trace that can be persisted and reused in prompts.
    """
    commands: list[str] = []
    for msg in messages or []:
        if not isinstance(msg, ToolCallRequestEvent):
            continue
        for fc in msg.content:
            if getattr(fc, "name", "") != "bash":
                continue
            cmd = _extract_bash_command(getattr(fc, "arguments", ""))
            if cmd:
                commands.append(cmd)

    # Keep only mutation-relevant shell commands to reduce noise.
    mutation_cmds = [
        c for c in commands
        if "/testcase/variant_" in c or "/testcase/mutate.py" in c
    ]
    variant_generation: dict[str, list[str]] = {}
    for cmd in mutation_cmds:
        # Track which command produced which variant path(s).
        for match in re.findall(r"/testcase/variant_[^ \n\t\"'`;|)]+", cmd):
            import posixpath
            base = posixpath.basename(match)
            variant_generation.setdefault(base, []).append(cmd)

    assistant_summary = ""
    for msg in reversed(messages or []):
        text = _content_to_str(getattr(msg, "content", ""))
        if text and text.strip():
            assistant_summary = _truncate(text.strip(), 2000)
            break

    return {
        "num_bash_calls": len(commands),
        "mutation_commands": mutation_cmds[:30],
        "variant_generation": {k: v[:5] for k, v in variant_generation.items()},
        "assistant_summary": assistant_summary,
    }


def _persist_mutation_attempt_artifacts(
    container_id: str,
    results_dir: str,
    instance_id: str,
    round_num: int,
    attempt_num: int,
    crash_reports: list[dict],
    trace: dict,
) -> dict:
    """Persist mutation attempt artifacts for offline replay/analysis."""
    safe_id = _safe_instance_id(instance_id)
    attempt_dir = os.path.join(
        results_dir,
        "mutation_artifacts",
        safe_id,
        f"round_{round_num}",
        f"attempt_{attempt_num}",
    )
    variants_dir = os.path.join(attempt_dir, "variants")
    repro_dir = os.path.join(attempt_dir, "repro_outputs")
    os.makedirs(variants_dir, exist_ok=True)
    os.makedirs(repro_dir, exist_ok=True)

    persisted_reports: list[dict] = []
    for r in crash_reports:
        variant = r.get("variant", "")
        src_path = r.get("path", "")
        variant_host_path = os.path.join(variants_dir, variant) if variant else ""
        copied_ok = False
        copy_msg = "missing source path"
        if src_path and variant_host_path:
            copied_ok, copy_msg = copy_from_container(
                container_id, src_path, variant_host_path
            )

        repro_log_path = os.path.join(repro_dir, f"{variant}.log") if variant else ""
        if repro_log_path:
            with open(repro_log_path, "w", encoding="utf-8") as f:
                f.write(r.get("raw_output", ""))

        persisted_reports.append({
            "variant": variant,
            "container_path": src_path,
            "host_variant_path": variant_host_path,
            "variant_copied": copied_ok,
            "variant_copy_message": copy_msg,
            "repro_log_path": repro_log_path,
            "exit_code": r.get("exit_code"),
            "crashed": r.get("crashed"),
            "vuln_type": r.get("vuln_type", "unknown"),
            "file_sha256": r.get("file_sha256", ""),
            "mutation_how": r.get("mutation_how", ""),
            "mutation_commands": r.get("mutation_commands", []),
            "output_snippet": r.get("output", ""),
        })

    metadata = {
        "instance_id": instance_id,
        "round": round_num,
        "attempt": attempt_num,
        "num_variants": len(crash_reports),
        "num_crashed": sum(1 for x in crash_reports if x.get("crashed")),
        "num_not_crashed": sum(1 for x in crash_reports if not x.get("crashed")),
        "trace": trace,
        "variants": persisted_reports,
    }
    meta_path = os.path.join(attempt_dir, "metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    return {
        "artifact_dir": attempt_dir,
        "metadata_path": meta_path,
        "num_variants": metadata["num_variants"],
        "num_crashed": metadata["num_crashed"],
        "num_not_crashed": metadata["num_not_crashed"],
    }


def _get_repo_root(container_id: str) -> str:
    """Extract the git repo root path from the secb patch() function.

    The ``patch()`` function in ``/usr/local/bin/secb`` always contains a
    ``cd /src/<project>`` line which is the repo root.
    """
    try:
        secb_content = read_file(container_id, "/usr/local/bin/secb")
        match = re.search(r'patch\s*\(\)\s*\{.*?cd\s+(/src/\S+)', secb_content, re.DOTALL)
        if match:
            return match.group(1).strip()
    except Exception:
        pass
    # Fallback: find any git repo under /src
    exit_code, stdout, stderr = exec_cmd(
        container_id,
        "find /src -maxdepth 2 -name .git -type d | head -1",
    )
    if exit_code == 0 and stdout.strip():
        import posixpath
        return posixpath.dirname(stdout.strip())
    return "/src"


# ---------------------------------------------------------------------------
# Variant collection (after Mutator agent finishes)
# ---------------------------------------------------------------------------


def _collect_variant_results(
    container_id: str,
    repro_cmd: ReproCommand,
    round_num: int = 0,
    orig_vuln_type: str = "unknown",
    mutation_trace: dict | None = None,
) -> list[dict]:
    """Scan /testcase/variant_* files and run each, collecting crash reports.

    The ``round_num`` is prefixed to variant names so that variants from
    different rounds have unique identifiers in ``all_crash_reports``.

    A variant is marked ``crashed=True`` only when its sanitizer output
    matches the SAME vulnerability type as the original PoC (determined
    by ``orig_vuln_type``).  This prevents unrelated sanitizer errors from
    polluting the crash/no-crash differential used by the Analyzer.
    """
    # List variant files
    exit_code, stdout, _ = exec_cmd(
        container_id, "ls -1 /testcase/variant_* 2>/dev/null"
    )
    if exit_code != 0 or not stdout.strip():
        logger.warning("No variant files found in /testcase/")
        return []

    variant_paths = [p.strip() for p in stdout.strip().splitlines() if p.strip()]
    crash_reports: list[dict] = []

    import posixpath

    for vpath in variant_paths:
        base_name = posixpath.basename(vpath)
        variant_name = f"r{round_num}_{base_name}"
        # Persist the file with a round-prefixed name so it survives across
        # rounds and can be used in cumulative variant robustness testing.
        persisted_path = f"/testcase/{variant_name}"
        exec_cmd(container_id, f"cp '{vpath}' '{persisted_path}'")

        try:
            if repro_cmd.poc_type == "script":
                cmd = f"bash {persisted_path}"
            else:
                cmd = repro_cmd.build_cmd(persisted_path)
            exit_code, output = run_custom_repro(container_id, cmd)
            crashed = _matches_vuln_type(output, orig_vuln_type)
            variant_type = extract_vuln_type(output)
            h_exit, h_out, _ = exec_cmd(
                container_id, f"sha256sum '{persisted_path}' | awk '{{print $1}}'"
            )
            file_sha256 = h_out.strip() if h_exit == 0 else ""
            gen_map = mutation_trace.get("variant_generation", {}) if isinstance(mutation_trace, dict) else {}
            mutation_cmds = gen_map.get(base_name, []) if isinstance(gen_map, dict) else []
            mutation_how = " | ".join(mutation_cmds[:2]) if mutation_cmds else (
                mutation_trace.get("assistant_summary", "")[:300]
                if isinstance(mutation_trace, dict) else ""
            )
            crash_reports.append({
                "round": round_num,
                "base_variant": base_name,
                "variant": variant_name,
                "path": persisted_path,
                "exit_code": exit_code,
                "raw_output": output,
                "output": _truncate(output),
                "crashed": crashed,
                "vuln_type": variant_type,
                "file_sha256": file_sha256,
                "mutation_how": mutation_how,
                "mutation_commands": mutation_cmds[:3],
            })
            logger.info(
                "Variant %s: exit=%d, crashed=%s (orig_type=%s, variant_type=%s)",
                variant_name, exit_code, crashed,
                orig_vuln_type, variant_type,
            )
        except Exception as e:
            logger.warning("Failed to run variant %s: %s", variant_name, e)

    return crash_reports


# ---------------------------------------------------------------------------
# Mutation stage
# ---------------------------------------------------------------------------


async def _mutate(
    model_client: OpenAIChatCompletionClient,
    container_id: str,
    repro_cmd: ReproCommand,
    orig_poc: str,
    orig_output: str,
    instance: dict,
    round_num: int,
    prev_patch: str = "",
    prev_feedback: str = "",
    prev_crash_reports: list[dict] | None = None,
    property_info: str = "",
    mutation_guidance: str = "",
    orig_vuln_type: str = "unknown",
    traj_path: str = "",
) -> tuple[list[dict], dict]:
    """Generate and execute PoC variants.

    Returns ``(crash_reports, mutation_trace)``.
    """
    logger.info(
        "Round %d: Mutating PoC (type=%s, targeted=%s)",
        round_num, repro_cmd.poc_type, round_num > 0,
    )

    targeted = round_num > 0
    ext = _get_extension(repro_cmd.poc_path)

    # Clean up temporary Mutator artifacts but keep persisted round-prefixed
    # variant files (r<N>_variant_*) so they remain available for cumulative
    # robustness testing across rounds.
    exec_cmd(container_id, "rm -f /testcase/mutate.py")
    # Remove only the raw variant_* files (Mutator's output), not r<N>_ prefixed ones
    exec_cmd(
        container_id,
        "for f in /testcase/variant_*; do [ -e \"$f\" ] && rm -f \"$f\"; done",
    )

    mutator = create_mutator(
        model_client,
        container_id,
        num_variants=MAX_MUTATION_VARIANTS,
        poc_path=repro_cmd.poc_path,
        poc_type=repro_cmd.poc_type,
        repro_cmd=repro_cmd.cmd_template or f"{repro_cmd.binary} {repro_cmd.args} {{poc}}",
        ext=ext,
        targeted=targeted,
    )

    # Build the task prompt
    if targeted:
        prev_crashes_text = ""
        variant_corpus_text = ""
        if prev_crash_reports:
            for r in prev_crash_reports:
                if r["crashed"]:
                    prev_crashes_text += f"- {r['variant']} (exit={r['exit_code']}): CRASHED\n"
                else:
                    prev_crashes_text += f"- {r['variant']}: did NOT crash\n"
                variant_corpus_text += (
                    f"- {r.get('path', '')} "
                    f"[{'CRASHED' if r.get('crashed') else 'NO-CRASH'}]\n"
                )

        task = f"""\
Generate {MAX_MUTATION_VARIANTS} TARGETED PoC variants for this vulnerability.

## Bug Description
{instance.get('bug_report', 'N/A')}

## Original PoC ({repro_cmd.poc_path}, type={repro_cmd.poc_type})
{_truncate(orig_poc) if repro_cmd.poc_type == 'text' else f'Binary file ({len(orig_poc)} bytes). Use bash to examine: xxd /testcase/poc | head -20'}

## Original sanitizer output
```
{_truncate(orig_output)}
```

## Previous Patch Attempt (insufficient)
```diff
{_truncate(prev_patch, 1500)}
```

## Patch Failure Feedback
{prev_feedback}

## Previous Variant Results
{prev_crashes_text}

## Existing Variant Corpus (reuse as mutation seeds)
{variant_corpus_text if variant_corpus_text else "No previous variants available."}

## Unresolved Safety Properties
{property_info if property_info else "No property analysis available yet."}

{mutation_guidance}

Create variants that specifically probe code paths the previous patch did NOT cover.
If unresolved safety properties are listed above, design variants targeting their boundary conditions.
Prefer mutating existing variant files under /testcase/r*_variant_* to form
clear parent->child mutation chains. Keep both crash and non-crash variants.
"""
    else:
        poc_display = _truncate(orig_poc) if repro_cmd.poc_type == "text" else \
            f"Binary file. Use bash to examine: xxd {repro_cmd.poc_path} | head -20"
        task = f"""\
Generate {MAX_MUTATION_VARIANTS} PoC variants for this vulnerability.

## Bug Description
{instance.get('bug_report', 'N/A')}

## Original PoC ({repro_cmd.poc_path}, type={repro_cmd.poc_type})
{poc_display}

## Sanitizer Report
```
{_truncate(orig_output)}
```

{mutation_guidance}

Create variants that trigger the same vulnerability through different code paths.
"""

    result = await _run_with_retry(mutator, task)

    # Save trajectory
    if traj_path and result.messages:
        append_agent_trajectory(traj_path, f"mutator_r{round_num}", result.messages)
    mutation_trace = _extract_mutator_trace(result.messages)
    crash_reports = _collect_variant_results(
        container_id, repro_cmd, round_num=round_num,
        orig_vuln_type=orig_vuln_type,
        mutation_trace=mutation_trace,
    )

    logger.info(
        "Round %d mutation: %d variants found, %d crashed",
        round_num,
        len(crash_reports),
        sum(1 for r in crash_reports if r["crashed"]),
    )
    return crash_reports, mutation_trace


# ---------------------------------------------------------------------------
# Analysis stage (differential property discovery)
# ---------------------------------------------------------------------------


async def _analyze(
    analyzer: AssistantAgent,
    container_id: str,
    repo_root: str,
    orig_output: str,
    all_crash_reports: list[dict],
    new_crash_reports: list[dict],
    instance: dict,
    round_num: int,
    repro_cmd_str: str = "",
    prev_patch: str = "",
    prev_feedback: str = "",
    traj_path: str = "",
) -> str:
    """Differential property discovery: deduce safety properties from crash reports.

    The *analyzer* agent is reused across rounds so it retains memory of
    previous tool calls and reasoning.  On round 0 we send the full context;
    on subsequent rounds we send only the incremental information (new
    variants, patch feedback) and ask the agent to refine its analysis.

    The Analyzer may insert diagnostic probes (fprintf) into source code,
    build, and run the PoC to observe runtime values.  After the Analyzer
    finishes, the pipeline calls reset_source() to remove all probe edits
    before Patchers run.

    Returns the property_report text (structured markdown).
    """
    logger.info("Analyzing: differential property discovery (round %d)", round_num)

    probe_instructions = f"""
## Build & Run Instructions (for dynamic probes)
- Build command: `bash("secb build 2>&1 | tail -30")`
- Repro command: `bash("{repro_cmd_str}")`
- After inserting probes, build and run to observe PROBE output.
- You may iterate: insert probes, build, run, analyse, insert more probes.
""" if repro_cmd_str else ""

    if round_num == 0:
        # --- First round: full context ---
        crash_summary = f"### Original PoC crash\n```\n{_truncate(orig_output)}\n```\n\n"
        for report in all_crash_reports:
            status = "CRASHED" if report["crashed"] else "DID NOT CRASH"
            mutation_line = report.get("mutation_how", "")
            mutation_text = mutation_line if mutation_line else "N/A"
            crash_summary += (
                f"### {report['variant']} ({status}, exit={report['exit_code']})\n"
                f"Mutation lineage: {mutation_text}\n"
                f"```\n{report['output']}\n```\n\n"
            )

        task = f"""\
Analyse the following crash reports and derive violated safety properties.

## Bug Description
{instance.get('bug_report', 'N/A')}

## Crash Reports
{crash_summary}

The source code is in {repo_root}/. Read relevant files to understand the \
code semantics and derive precise safety properties.
{probe_instructions}
Use dynamic probes to verify your hypotheses about the root cause before \
finalising the Property Analysis Report.
"""
    else:
        # --- Subsequent rounds: incremental context only ---
        new_crash_summary = ""
        for report in new_crash_reports:
            status = "CRASHED" if report["crashed"] else "DID NOT CRASH"
            mutation_line = report.get("mutation_how", "")
            mutation_text = mutation_line if mutation_line else "N/A"
            new_crash_summary += (
                f"### {report['variant']} ({status}, exit={report['exit_code']})\n"
                f"Mutation lineage: {mutation_text}\n"
                f"```\n{report['output']}\n```\n\n"
            )

        task = f"""\
New round of analysis. Here are the NEW variant crash reports from this round:

## New Crash Reports
{new_crash_summary if new_crash_summary else "No new variants this round."}

## Previous Patch Attempt
```diff
{_truncate(prev_patch, 1500)}
```

## Patch Feedback
{prev_feedback}
{probe_instructions}
Refine your previous property analysis based on the new evidence. Some \
properties may have been addressed by the previous patch; focus on those \
that remain unresolved. Use dynamic probes if needed to verify remaining \
hypotheses. Produce an updated Property Analysis Report.
"""

    result = await _run_with_retry(analyzer, task)

    # Save trajectory
    if traj_path and result.messages:
        append_agent_trajectory(traj_path, f"analyzer_r{round_num}", result.messages)

    # Clean up any probe edits the Analyzer inserted
    reset_source(container_id)

    # Verify the reset actually produced a clean workspace
    _exit, _status_out, _ = exec_cmd(
        container_id, f"cd {repo_root} && git status --porcelain"
    )
    if _exit == 0 and _status_out.strip():
        logger.warning(
            "Workspace not clean after reset_source, forcing second reset. "
            "Dirty files: %s", _status_out.strip()[:200],
        )
        reset_source(container_id)

    # Extract the Property Analysis Report from Analyzer messages.
    property_report = ""
    _REPORT_MARKER = "# Property Analysis Report"

    if result.messages:
        for msg in reversed(result.messages):
            text = _content_to_str(getattr(msg, "content", ""))
            if _REPORT_MARKER in text:
                property_report = text
                break

        if not property_report:
            for msg in reversed(result.messages):
                text = _content_to_str(getattr(msg, "content", ""))
                if text and len(text) > 100:
                    property_report = text
                    break

    logger.info(
        "Analyzer produced property report of %d chars", len(property_report)
    )
    return property_report


def _build_property_feedback(
    property_report: str,
    variant_result: dict,
    all_crash_reports: list[dict],
) -> str:
    """Cross-reference property report with variant test results to build
    property-level feedback for the next round.

    Returns a feedback string guiding subsequent Mutator and Patcher.
    """
    lines: list[str] = []

    total = variant_result.get("total", 0)
    still_crashed = variant_result.get("still_crashed", 0)

    lines.append(
        f"The patch passed the original PoC but {still_crashed}/{total} "
        f"variant PoCs still trigger sanitizer errors."
    )

    # List variants that still crash
    details = variant_result.get("details", [])
    crashed_variants = [d["variant"] for d in details if d.get("crashed_after_patch")]
    if crashed_variants:
        lines.append("")
        lines.append("Variants still crashing after patch:")
        for v in crashed_variants:
            # Find the original crash report for context
            orig = next((r for r in all_crash_reports if r["variant"] == v), None)
            if orig:
                lines.append(f"- {v}: {_truncate(orig.get('output', ''), 300)}")
            else:
                lines.append(f"- {v}")

    if property_report:
        lines.append("")
        lines.append("## Property-Level Assessment")
        lines.append(
            "The following property analysis was performed before patching. "
            "Some properties may have been addressed, but the remaining "
            "crashes suggest at least some properties are still violated:"
        )
        lines.append(property_report)

    lines.append("")
    lines.append(
        "Generate a more comprehensive fix that addresses ALL identified "
        "safety properties, especially those related to the still-crashing variants."
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Patch stage (parallel beam-search patching)
# ---------------------------------------------------------------------------


def _build_patcher_task(
    repo_root: str,
    orig_output: str,
    all_crash_reports: list[dict],
    new_crash_reports: list[dict],
    instance: dict,
    round_num: int,
    property_report: str = "",
    all_patches_feedback: list[dict] | None = None,
    experience_prompt: str = "",
) -> str:
    """Build the task prompt for a Patcher agent.

    This is extracted from the old ``_patch`` so that every parallel Patcher
    receives the same prompt (but may produce different edits due to high
    temperature sampling).
    """
    property_section = ""
    if property_report:
        property_section = f"""
## Property Analysis
{property_report}

The above properties were derived from differential analysis of crash vs \
non-crash variants. Ensure ALL HIGH-confidence properties hold after your fix.
"""

    # Build historical patch feedback section
    history_section = ""
    if all_patches_feedback:
        history_section = "\n## Historical Patch Attempts (all failed or insufficient)\n"
        for i, pf in enumerate(all_patches_feedback, 1):
            history_section += f"""
### Attempt {i} (round {pf.get('round', '?')})
```diff
{_truncate(pf.get('patch', ''), 1000)}
```
Feedback: {_truncate(pf.get('feedback', ''), 500)}
"""

    if round_num == 0 and not all_patches_feedback:
        # --- First round, no history ---
        crash_summary = f"## Original PoC crash\n```\n{_truncate(orig_output)}\n```\n\n"
        for report in all_crash_reports:
            status = "CRASHED" if report["crashed"] else "DID NOT CRASH"
            crash_summary += (
                f"## {report['variant']} ({status}, exit={report['exit_code']})\n"
                f"```\n{report['output']}\n```\n\n"
            )

        task = f"""\
Analyse and fix this vulnerability.

## Bug Description
{instance.get('bug_report', 'N/A')}

## Crash Reports
{crash_summary}

{property_section}

{experience_prompt}

Read the relevant source files, identify the root cause, and edit the \
code to fix the vulnerability. The source code is in {repo_root}/.
"""
    else:
        # --- Subsequent rounds or rounds with history ---
        new_crash_summary = ""
        for report in new_crash_reports:
            status = "CRASHED" if report["crashed"] else "DID NOT CRASH"
            new_crash_summary += (
                f"## {report['variant']} ({status}, exit={report['exit_code']})\n"
                f"```\n{report['output']}\n```\n\n"
            )

        # On round 0 with history (shouldn't normally happen), include full context
        if round_num == 0:
            crash_summary = f"## Original PoC crash\n```\n{_truncate(orig_output)}\n```\n\n"
            for report in all_crash_reports:
                status = "CRASHED" if report["crashed"] else "DID NOT CRASH"
                crash_summary += (
                    f"## {report['variant']} ({status}, exit={report['exit_code']})\n"
                    f"```\n{report['output']}\n```\n\n"
                )
            task = f"""\
Analyse and fix this vulnerability.

## Bug Description
{instance.get('bug_report', 'N/A')}

## Crash Reports
{crash_summary}

{history_section}

{property_section}

{experience_prompt}

Read the relevant source files, identify the root cause, and edit the \
code to fix the vulnerability. The source code is in {repo_root}/.
"""
        else:
            task = f"""\
Previous patches were insufficient. The source has been reset to the \
original state. You need to produce a NEW, more comprehensive fix.

## Bug Description
{instance.get('bug_report', 'N/A')}

## Original PoC crash
```
{_truncate(orig_output)}
```

## New Variant Crash Reports
{new_crash_summary if new_crash_summary else "No new variants this round."}

{history_section}

{property_section}

{experience_prompt}

Analyse why previous patches were insufficient and produce a better fix. \
Read the source files before editing. The source code is in {repo_root}/.
"""

    return task


def _git_diff(container_id: str, repo_root: str) -> str:
    """Stage new source files and return ``git diff`` output.

    Uses ``NO_COLOR=1`` and ``--no-color`` to guarantee the output has no
    ANSI escape codes, which would corrupt the diff when re-applied.
    """
    exec_cmd(
        container_id,
        f"cd {repo_root} && "
        "git ls-files --others --exclude-standard "
        "| grep -E '\\.(c|h|cpp|hpp|cc|cxx|hxx|py|js|ts|rb|java|go|rs|lua|pl|sh|S|s|inc)$' "
        "| xargs -r git add --intent-to-add 2>/dev/null; true",
    )
    exit_code, stdout, _stderr = exec_cmd(
        container_id,
        f"cd {repo_root} && NO_COLOR=1 git --no-pager diff --no-color",
    )
    if exit_code != 0 or not stdout:
        return ""
    # Keep patch text byte-for-byte (except ensuring a final newline).
    # Using .strip() can drop trailing context lines like " " in unified diff,
    # which corrupts hunk line counts and makes git apply fail.
    return stdout if stdout.endswith("\n") else (stdout + "\n")


async def _patch_single(
    patcher: AssistantAgent,
    container_id: str,
    repo_root: str,
    task: str,
    expected_exit_code: int = 0,
    orig_vuln_type: str = "unknown",
    model_client: OpenAIChatCompletionClient | None = None,
    traj_path: str = "",
    patcher_key: str = "",
) -> dict:
    """Run a single Patcher agent and verify **in-place** (like MemRepair).

    The Patcher edits files via tools bound to *container_id*. After it
    finishes we:
      1. Collect ``git diff`` (for recording only, never re-applied).
      2. Build the project (``secb build``).
      3. Run ``secb repro`` to verify the vulnerability is fixed.

    By verifying in the SAME container where edits were made, we avoid
    the error-prone step of re-applying diffs to a different container.
    The diff is only used for saving to disk, never for ``git apply``.

    Returns a dict with keys: ``diff``, ``verified``, ``feedback``.
    """
    for attempt in range(1 + MAX_PATCHER_RETRIES):
        # Ensure clean git state before edits
        reset_source(container_id)

        result = await _run_with_retry(patcher, task)

        # Save trajectory
        if traj_path and patcher_key and result.messages:
            suffix = f"_retry{attempt}" if attempt > 0 else ""
            append_agent_trajectory(
                traj_path, f"{patcher_key}{suffix}", result.messages,
            )

        # Diagnostic: log what the Patcher actually did
        if result.messages:
            tool_calls = 0
            edit_calls = 0
            for msg in result.messages:
                content = _content_to_str(getattr(msg, "content", ""))
                if isinstance(msg, ToolCallRequestEvent):
                    tool_calls += len(msg.content)
                if "str_replace_edit" in content or "Successfully edited" in content:
                    edit_calls += 1
            last_text = ""
            for msg in reversed(result.messages):
                text = _content_to_str(getattr(msg, "content", ""))
                if text and len(text) > 20:
                    last_text = text[:500]
                    break
            logger.info(
                "%s diagnostics: %d messages, ~%d tool calls, ~%d edit-related, "
                "last msg: %.300s",
                patcher.name, len(result.messages), tool_calls, edit_calls,
                last_text.replace("\n", " | "),
            )

        # --- Gate 1: non-empty diff ---
        _gs_exit, _gs_out, _ = exec_cmd(
            container_id, f"cd {repo_root} && git status --short"
        )
        if _gs_exit == 0:
            logger.info(
                "%s git status after editing: %s",
                patcher.name,
                _gs_out.strip()[:300] if _gs_out.strip() else "(clean)",
            )

        patch_diff = _git_diff(container_id, repo_root)

        if not patch_diff:
            if attempt < MAX_PATCHER_RETRIES and model_client is not None:
                logger.warning(
                    "%s produced no git diff, retrying within round (attempt %d/%d)",
                    patcher.name, attempt + 1, 1 + MAX_PATCHER_RETRIES,
                )
                patcher = create_patcher(
                    model_client, container_id, name=patcher.name,
                )
                task = (
                    "Your previous attempt produced NO source code changes. "
                    "You MUST use the str_replace_edit tool to edit files — "
                    "do NOT just describe changes verbally.\n\n" + task
                )
                continue
            else:
                logger.warning("%s produced no git diff (final)", patcher.name)
                return {"diff": "", "verified": False, "feedback": "No changes made"}

        # --- Gate 2: build in-place ---
        build_ok, build_msg = build_project(container_id)
        if not build_ok:
            if attempt < MAX_PATCHER_RETRIES and model_client is not None:
                logger.warning(
                    "%s diff failed to build, retrying within round (attempt %d/%d)",
                    patcher.name, attempt + 1, 1 + MAX_PATCHER_RETRIES,
                )
                patcher = create_patcher(
                    model_client, container_id, name=patcher.name,
                )
                task = (
                    "Your previous patch FAILED to compile. Build errors:\n"
                    f"```\n{_truncate(build_msg, 2000)}\n```\n"
                    "Fix the compilation errors and produce a corrected patch.\n\n"
                    + task
                )
                continue
            else:
                logger.warning("%s build failed, retries exhausted", patcher.name)
                return {
                    "diff": patch_diff,
                    "verified": False,
                    "feedback": f"Build failed:\n{_truncate(build_msg)}",
                }

        # --- Gate 3: in-place repro verification (like MemRepair) ---
        repro_exit, repro_out = run_repro(container_id)
        sanitizer_error = _matches_vuln_type(repro_out, orig_vuln_type)
        exit_ok = repro_exit == 0 or repro_exit == expected_exit_code

        if exit_ok and not sanitizer_error:
            logger.info(
                "%s patch VERIFIED in-place (exit=%d, no sanitizer error)",
                patcher.name, repro_exit,
            )
            return {"diff": patch_diff, "verified": True, "feedback": ""}
        else:
            reasons: list[str] = []
            if sanitizer_error:
                reasons.append("same-type sanitizer still triggers")
            if not exit_ok:
                reasons.append(
                    f"exit_code={repro_exit} not in accepted set {{0, {expected_exit_code}}}"
                )
            reason_text = "; ".join(reasons) if reasons else "verification gate not satisfied"
            feedback = (
                f"Patch builds but verification failed: {reason_text}.\n"
                f"Repro output:\n{_truncate(repro_out, 1500)}"
            )
            logger.warning(
                "%s patch did not pass verification; defer improvement to next adversarial round",
                patcher.name,
            )
            return {"diff": patch_diff, "verified": False, "feedback": feedback}

    return {"diff": "", "verified": False, "feedback": "All retries exhausted"}


async def _patch_parallel(
    model_client: OpenAIChatCompletionClient,
    main_container_id: str,
    image: str,
    repo_root: str,
    task: str,
    expected_exit_code: int = 0,
    orig_vuln_type: str = "unknown",
    count: int = PATCHES_PER_ROUND,
    traj_path: str = "",
    round_num: int = 0,
) -> list[dict]:
    """Launch *count* Patcher agents in parallel containers.

    Each Patcher runs in its own container with in-place verification
    (build + repro, like MemRepair).  Returns a list of result dicts
    with keys: ``diff``, ``verified``, ``feedback``.  Diffs are
    deduplicated.
    """
    logger.info("Starting %d parallel Patcher containers", count)
    container_ids = start_patcher_containers(image, count)

    # Create a high-temperature model client for diverse sampling
    hot_client = create_model_client(temperature=PATCHER_TEMPERATURE)

    try:
        patchers = [
            create_patcher(hot_client, cid, name=f"Patcher_{i}")
            for i, cid in enumerate(container_ids)
        ]

        tasks = [
            _patch_single(
                p, cid, repo_root, task,
                expected_exit_code=expected_exit_code,
                orig_vuln_type=orig_vuln_type,
                model_client=hot_client,
                traj_path=traj_path,
                patcher_key=f"patcher_r{round_num}_{i}",
            )
            for i, (p, cid) in enumerate(zip(patchers, container_ids))
        ]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect and deduplicate
        seen: set[str] = set()
        patch_results: list[dict] = []
        for i, r in enumerate(raw_results):
            if isinstance(r, Exception):
                logger.warning("Patcher_%d failed with exception: %s", i, r)
                continue
            if not isinstance(r, dict) or not r.get("diff"):
                continue
            normalized = r["diff"].strip()
            if normalized not in seen:
                seen.add(normalized)
                patch_results.append(r)

        num_verified = sum(1 for r in patch_results if r.get("verified"))
        logger.info(
            "Parallel patching: %d diffs collected (%d verified) from %d patchers",
            len(patch_results), num_verified, count,
        )
        return patch_results

    finally:
        stop_containers(container_ids)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _test_variants_against_patch(
    container_id: str,
    repro_cmd: ReproCommand,
    all_crash_reports: list[dict],
    orig_vuln_type: str = "unknown",
) -> dict:
    """After a patch passes the original PoC, test all previous variants.

    Uses ``_matches_vuln_type`` to check whether variants still trigger
    the SAME vulnerability type after patching (consistent with how
    variants are classified during collection).

    Returns {'total': N, 'still_crashed': M, 'details': [...]}.
    """
    details = []
    still_crashed = 0

    for report in all_crash_reports:
        vpath = report.get("path", "")
        if not vpath:
            continue

        try:
            check_code, _, _ = exec_cmd(
                container_id, f"test -f {vpath} && echo ok"
            )
            if check_code != 0:
                continue
            if repro_cmd.poc_type == "script":
                cmd = f"bash {vpath}"
            else:
                cmd = repro_cmd.build_cmd(vpath)
            exit_code, output = run_custom_repro(container_id, cmd)
            crashed = _matches_vuln_type(output, orig_vuln_type)
            if crashed:
                still_crashed += 1
            details.append({
                "variant": report["variant"],
                "crashed_after_patch": crashed,
                "exit_code": exit_code,
            })
        except Exception as e:
            logger.warning("Failed to test variant %s after patch: %s", report["variant"], e)

    return {
        "total": len(details),
        "still_crashed": still_crashed,
        "details": details,
    }


# ---------------------------------------------------------------------------
# Selector
# ---------------------------------------------------------------------------


async def _select_best_patch(
    model_client: OpenAIChatCompletionClient,
    candidates: list[dict],
    traj_path: str = "",
) -> dict:
    """Use the Selector agent to pick the best patch from candidates."""
    if len(candidates) == 1:
        return candidates[0]

    candidates_text = ""
    for i, c in enumerate(candidates):
        vr = c.get("variant_test_result", {})
        candidates_text += f"""\
### Candidate {i + 1} (from round {c['round']})

**Patch:**
```diff
{_truncate(c['patch'], 1500)}
```

**Variant robustness:** {vr.get('total', 0)} variants tested, \
{vr.get('still_crashed', 0)} still crashed after patch.

---
"""

    task = f"""\
Select the best patch from the following {len(candidates)} candidates.

{candidates_text}

Which candidate is the most robust and correct fix?
"""

    selector = create_selector(model_client)
    result = await _run_with_retry(selector, task)

    # Save trajectory
    if traj_path and result.messages:
        append_agent_trajectory(traj_path, "selector", result.messages)

    response = _content_to_str(
        result.messages[-1].content if result.messages else ""
    )

    idx = _extract_selected_index(response)
    if idx is not None and 1 <= idx <= len(candidates):
        selected = candidates[idx - 1]
        selected["selector_reason"] = response
        return selected

    # Fallback: pick the one with fewest still-crashing variants
    best = min(
        candidates,
        key=lambda c: c.get("variant_test_result", {}).get("still_crashed", 999),
    )
    best["selector_reason"] = "Fallback: selected candidate with fewest still-crashing variants."
    return best


# ---------------------------------------------------------------------------
# Main pipeline entry point
# ---------------------------------------------------------------------------


async def solve_instance(
    instance: dict,
    model_client: OpenAIChatCompletionClient,
    results_dir: str = "results",
) -> dict:
    """Run the adversarial pipeline for one SEC-bench instance.

    Args:
        instance: A single row from the SEC-bench dataset.
        model_client: The shared LLM client.
        results_dir: Directory for result and trajectory files.

    Returns:
        A result dict with status, patch, metadata, etc.
    """
    instance_id = instance["instance_id"]
    logger.info("=" * 60)
    logger.info("Solving instance: %s", instance_id)
    logger.info("=" * 60)

    # Initialize trajectory file
    traj_path = os.path.join(results_dir, f"{instance_id}.traj.json")
    init_trajectory(traj_path, instance_id)

    container_id = None
    try:
        # === Stage 0: Environment Setup ===
        image = get_image_name(instance_id)
        logger.info("Starting container from image: %s", image)
        container_id = start_container(image)

        # Build the project
        build_ok, build_msg = build_project(container_id)
        if not build_ok:
            logger.error("Initial build failed for %s", instance_id)
            return {
                "instance_id": instance_id,
                "status": "build_failed",
                "error": _truncate(build_msg, 500),
                "token_usage": summarize_token_usage(traj_path),
            }

        # Verify original PoC triggers the bug
        orig_exit_code, orig_output = run_repro(container_id)
        if not _has_sanitizer_error(orig_output):
            logger.warning(
                "Original PoC may not trigger sanitizer error for %s (exit=%d)",
                instance_id, orig_exit_code,
            )

        # Parse repro command and get repo root
        repro_cmd = parse_repro_command(instance.get("secb_sh", ""))
        try:
            expected_exit_code = int(instance.get("exit_code", 0))
        except (TypeError, ValueError):
            expected_exit_code = 0
        repo_root = _get_repo_root(container_id)
        logger.info("Repo root: %s", repo_root)

        # Read original PoC content
        try:
            orig_poc = read_file(container_id, repro_cmd.poc_path)
        except Exception:
            orig_poc = "<binary file - cannot display>"

        # Determine the canonical vulnerability type from the original crash
        orig_vuln_type = extract_vuln_type(orig_output)
        logger.info("Original vulnerability type: %s", orig_vuln_type)

        # === Stage 1: Adversarial Loop ===
        candidates = []
        all_crash_reports: list[dict] = []
        all_patches_feedback: list[dict] = []  # cross-round failed patch history
        mutation_attempt_records: list[dict] = []
        prev_property_report = ""
        experience_prompt = ""

        # Analyzer retains conversation history across rounds (cross-round memory).
        # Patchers are created fresh each round inside _patch_parallel.
        # E2 ablation: no variants, Analyzer uses single-crash prompt.
        analyzer_agent = create_analyzer(
            model_client, container_id,
            single_crash=ABLATION_SKIP_MUTATOR,
        )

        # Only force single round when BOTH Mutator and Analyzer are skipped (E1).
        # E2 (no Mutator but has Analyzer) still benefits from multi-round:
        # Analyzer can refine its analysis based on patch failure feedback.
        effective_rounds = (
            1 if (ABLATION_SKIP_MUTATOR and ABLATION_SKIP_ANALYZER)
            else MAX_ADVERSARIAL_ROUNDS
        )

        for round_num in range(effective_rounds):
            logger.info("=== Adversarial Round %d/%d ===", round_num + 1, effective_rounds)

            # --- Step 1: Mutate (with crash-validation gate) ---
            prev_patch = all_patches_feedback[-1]["patch"] if all_patches_feedback else ""
            prev_feedback = all_patches_feedback[-1]["feedback"] if all_patches_feedback else ""

            round_crash_reports = []
            if not ABLATION_SKIP_MUTATOR:
                # Retrieve mutation strategy guidance (static hints + past experiences)
                mutation_guidance = ""
                if round_num == 0:
                    vuln_type = extract_vuln_type(
                        instance.get("sanitizer_report", orig_output)
                    )
                    if not ABLATION_SKIP_MUTATION_EXP:
                        mut_experiences = retrieve_mutation_experiences(
                            results_dir=results_dir,
                            current_instance_id=instance_id,
                            repo=instance.get("repo", ""),
                            sanitizer_report=instance.get("sanitizer_report", orig_output),
                            bug_description=instance.get("bug_description", ""),
                        )
                        mutation_guidance = format_mutation_prompt(vuln_type, mut_experiences)
                    else:
                        # Ablation: skip retrieved experiences but keep static hints
                        mutation_guidance = format_mutation_prompt(vuln_type, [])

                mutation_feedback = ""
                for mutation_attempt in range(1 + MAX_MUTATION_RETRIES):
                    # Clean up previous attempt's variant files before retrying
                    if mutation_attempt > 0:
                        exec_cmd(
                            container_id,
                            "for f in /testcase/variant_*; do "
                            '[ -e "$f" ] && rm -f "$f"; done',
                        )
                        logger.info(
                            "Mutation gate not satisfied, retrying (attempt %d/%d)",
                            mutation_attempt + 1, 1 + MAX_MUTATION_RETRIES,
                        )

                    round_crash_reports, mutation_trace = await _mutate(
                        model_client=model_client,
                        container_id=container_id,
                        repro_cmd=repro_cmd,
                        orig_poc=orig_poc,
                        orig_output=orig_output,
                        instance=instance,
                        round_num=round_num,
                        prev_patch=prev_patch,
                        prev_feedback=(prev_feedback + "\n" + mutation_feedback).strip(),
                        prev_crash_reports=all_crash_reports if round_num > 0 else None,
                        property_info=prev_property_report if round_num > 0 else "",
                        mutation_guidance=mutation_guidance,
                        orig_vuln_type=orig_vuln_type,
                        traj_path=traj_path,
                    )
                    artifact_info = _persist_mutation_attempt_artifacts(
                        container_id=container_id,
                        results_dir=results_dir,
                        instance_id=instance_id,
                        round_num=round_num,
                        attempt_num=mutation_attempt + 1,
                        crash_reports=round_crash_reports,
                        trace=mutation_trace,
                    )
                    mutation_attempt_records.append({
                        "round": round_num,
                        "attempt": mutation_attempt + 1,
                        "artifact_dir": artifact_info.get("artifact_dir", ""),
                        "metadata_path": artifact_info.get("metadata_path", ""),
                        "num_variants": artifact_info.get("num_variants", 0),
                        "num_crashed": artifact_info.get("num_crashed", 0),
                        "num_not_crashed": artifact_info.get("num_not_crashed", 0),
                        "mutation_trace": mutation_trace,
                    })

                    num_crashed = sum(1 for r in round_crash_reports if r["crashed"])
                    num_not_crashed = sum(1 for r in round_crash_reports if not r["crashed"])

                    if num_crashed > 0 and num_not_crashed > 0:
                        logger.info(
                            "Mutation gate passed: %d crashed, %d did not crash",
                            num_crashed, num_not_crashed,
                        )
                        break

                    if num_crashed == 0:
                        mutation_feedback = (
                            "IMPORTANT: None of your previous variants triggered the "
                            f"target vulnerability ({orig_vuln_type}). You MUST produce "
                            "at least 1 variant that crashes with the SAME sanitizer "
                            "error type as the original PoC. Re-examine the original "
                            "PoC and sanitizer output carefully."
                        )
                    elif num_not_crashed == 0:
                        mutation_feedback = (
                            "IMPORTANT: ALL of your variants crashed — you also need "
                            "at least 1 variant that does NOT crash. The differential "
                            "between crashing and non-crashing inputs is essential for "
                            "root cause analysis. Try creating a variant that is "
                            "slightly below the trigger threshold (e.g. smaller input, "
                            "valid boundary values, correct field lengths)."
                        )

            all_crash_reports.extend(round_crash_reports)

            # --- Step 2: Analyze (property discovery) ---
            property_report = ""
            if not ABLATION_SKIP_ANALYZER:
                property_report = await _analyze(
                    analyzer=analyzer_agent,
                    container_id=container_id,
                    repo_root=repo_root,
                    orig_output=orig_output,
                    all_crash_reports=all_crash_reports,
                    new_crash_reports=round_crash_reports,
                    instance=instance,
                    round_num=round_num,
                    repro_cmd_str="secb repro",
                    prev_patch=prev_patch,
                    prev_feedback=prev_feedback,
                    traj_path=traj_path,
                )

            # --- Step 3: Parallel Patch (beam search) ---
            # Retrieve similar past fixes from the experience knowledge base
            if round_num == 0 and not ABLATION_SKIP_PATCHER_EXP:
                experiences = retrieve_experiences(
                    results_dir=results_dir,
                    current_instance_id=instance_id,
                    repo=instance.get("repo", ""),
                    sanitizer_report=instance.get("sanitizer_report", orig_output),
                    bug_description=instance.get("bug_description", ""),
                )
                experience_prompt = format_experience_prompt(experiences)

            task_prompt = _build_patcher_task(
                repo_root=repo_root,
                orig_output=orig_output,
                all_crash_reports=all_crash_reports,
                new_crash_reports=round_crash_reports,
                instance=instance,
                round_num=round_num,
                property_report=property_report,
                all_patches_feedback=all_patches_feedback if all_patches_feedback else None,
                experience_prompt=experience_prompt,
            )

            patch_results = await _patch_parallel(
                model_client=model_client,
                main_container_id=container_id,
                image=image,
                repo_root=repo_root,
                task=task_prompt,
                expected_exit_code=expected_exit_code,
                orig_vuln_type=orig_vuln_type,
                count=PATCHES_PER_ROUND,
                traj_path=traj_path,
                round_num=round_num,
            )

            if not patch_results:
                logger.warning("Round %d: no diffs produced by any Patcher", round_num + 1)
                all_patches_feedback.append({
                    "patch": "",
                    "feedback": (
                        "No Patcher produced any source code changes. "
                        "Make sure to use the str_replace_edit tool to edit source files."
                    ),
                    "round": round_num + 1,
                })
                prev_property_report = property_report
                continue

            # --- Step 4: Process in-place verification results ---
            # Patches were already verified in-place by _patch_single (like
            # MemRepair).  For verified patches we only need variant robustness
            # testing, which requires applying the diff to the main container
            # (where variant files live).
            round_has_perfect = False
            for pr in patch_results:
                if pr["verified"]:
                    # Run variant robustness test in main container
                    reset_source(container_id)
                    ok, msg = apply_patch(container_id, pr["diff"])
                    if not ok:
                        logger.warning(
                            "Round %d: verified patch failed to apply in main container: %s",
                            round_num + 1, msg[:200],
                        )
                        all_patches_feedback.append({
                            "patch": pr["diff"],
                            "feedback": f"Patch verified in-place but failed to apply in main container: {_truncate(msg)}",
                            "round": round_num + 1,
                        })
                        continue

                    build_ok, build_msg = build_project(container_id)
                    if not build_ok:
                        logger.warning(
                            "Round %d: verified patch failed to build in main container",
                            round_num + 1,
                        )
                        all_patches_feedback.append({
                            "patch": pr["diff"],
                            "feedback": f"Patch verified in-place but failed to build in main container: {_truncate(build_msg)}",
                            "round": round_num + 1,
                        })
                        continue

                    vr = _test_variants_against_patch(
                        container_id, repro_cmd, all_crash_reports,
                        orig_vuln_type=orig_vuln_type,
                    )
                    candidates.append({
                        "patch": pr["diff"],
                        "round": round_num + 1,
                        "analysis": "",
                        "property_report": property_report,
                        "variant_test_result": vr,
                    })
                    logger.info(
                        "Round %d: a patch PASSED (variants: %d/%d still crashed)",
                        round_num + 1,
                        vr.get("still_crashed", 0),
                        vr.get("total", 0),
                    )
                    if vr.get("still_crashed", 999) == 0:
                        round_has_perfect = True

                    # Add imperfect patches as feedback for next round
                    if vr.get("still_crashed", 0) > 0:
                        fb = _build_property_feedback(
                            property_report, vr, all_crash_reports
                        )
                        all_patches_feedback.append({
                            "patch": pr["diff"],
                            "feedback": fb,
                            "round": round_num + 1,
                        })
                else:
                    # Failed in-place verification
                    all_patches_feedback.append({
                        "patch": pr.get("diff", ""),
                        "feedback": pr.get("feedback", ""),
                        "round": round_num + 1,
                    })

            if round_has_perfect:
                logger.info("Round %d: perfect candidate found -- stopping early", round_num + 1)
                break

            prev_property_report = property_report

        # === Stage 2: Selection ===
        if not candidates:
            last_fb = all_patches_feedback[-1] if all_patches_feedback else {}
            _san_report = instance.get("sanitizer_report", orig_output)
            _vuln_type = extract_vuln_type(_san_report)
            save_mutation_experience(
                results_dir=results_dir,
                instance_id=instance_id,
                repo=instance.get("repo", ""),
                project_name=instance.get("project_name", ""),
                vuln_type=_vuln_type,
                crash_reports=all_crash_reports,
                sanitizer_report=_san_report,
                bug_description=instance.get("bug_description", ""),
                mutation_strategy_summary=_build_mutation_strategy_summary(
                    all_crash_reports, mutation_attempt_records,
                ),
            )
            return {
                "instance_id": instance_id,
                "status": "failed",
                "rounds": MAX_ADVERSARIAL_ROUNDS,
                "last_patch": last_fb.get("patch", ""),
                "last_feedback": last_fb.get("feedback", ""),
                "property_report": prev_property_report,
                "num_variants_total": len(all_crash_reports),
                "mutation_artifact_root": os.path.join(
                    results_dir, "mutation_artifacts", _safe_instance_id(instance_id)
                ),
                "token_usage": summarize_token_usage(traj_path),
            }

        if len(candidates) == 1:
            selected = candidates[0]
        else:
            logger.info("Selecting best patch from %d candidates", len(candidates))
            selected = await _select_best_patch(model_client, candidates, traj_path=traj_path)

        # Re-apply the selected patch for final state
        reset_source(container_id)
        apply_patch(container_id, selected["patch"])
        build_project(container_id)

        # Save successful experience to knowledge base (patch + mutation)
        _san_report = instance.get("sanitizer_report", orig_output)
        _vuln_type = extract_vuln_type(_san_report)
        save_experience(
            results_dir=results_dir,
            instance_id=instance_id,
            repo=instance.get("repo", ""),
            project_name=instance.get("project_name", ""),
            sanitizer_report=_san_report,
            bug_description=instance.get("bug_description", ""),
            patch=selected["patch"],
            property_report=selected.get("property_report", ""),
        )
        save_mutation_experience(
            results_dir=results_dir,
            instance_id=instance_id,
            repo=instance.get("repo", ""),
            project_name=instance.get("project_name", ""),
            vuln_type=_vuln_type,
            crash_reports=all_crash_reports,
            sanitizer_report=_san_report,
            bug_description=instance.get("bug_description", ""),
            mutation_strategy_summary=_build_mutation_strategy_summary(
                all_crash_reports, mutation_attempt_records,
            ),
        )

        return {
            "instance_id": instance_id,
            "status": "success",
            "patch": selected["patch"],
            "selected_round": selected["round"],
            "total_rounds": min(selected["round"], MAX_ADVERSARIAL_ROUNDS),
            "num_candidates": len(candidates),
            "variant_robustness": selected.get("variant_test_result", {}),
            "selector_reason": selected.get("selector_reason", ""),
            "property_report": selected.get("property_report", ""),
            "num_variants_total": len(all_crash_reports),
            "mutation_artifact_root": os.path.join(
                results_dir, "mutation_artifacts", _safe_instance_id(instance_id)
            ),
            "token_usage": summarize_token_usage(traj_path),
        }

    except Exception as e:
        logger.exception("Unexpected error solving %s", instance_id)
        return {
            "instance_id": instance_id,
            "status": "error",
            "error": str(e),
            "token_usage": summarize_token_usage(traj_path),
        }
    finally:
        if container_id:
            stop_container(container_id)
