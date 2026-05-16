"""Parse repro command templates from SEC-bench secb_sh field."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ReproCommand:
    """Structured representation of a SEC-bench repro command."""

    binary: str       # e.g. "/src/mruby/bin/mruby"
    args: str         # e.g. "" or "-xmt" or "-w -b 5"
    poc_path: str     # e.g. "/testcase/poc.rb"
    poc_type: str     # "text" | "binary" | "script"
    cmd_template: str = ""  # Full command with {poc} placeholder, e.g. "/src/ffmpeg -i {poc} -f null -"

    def build_cmd(self, poc_path: str | None = None) -> str:
        """Build the full command string, optionally replacing the PoC path."""
        target = poc_path or self.poc_path
        if self.cmd_template:
            return self.cmd_template.replace("{poc}", target)
        parts = [self.binary]
        if self.args:
            parts.append(self.args)
        parts.append(target)
        return " ".join(parts)


# File extensions considered as text-based PoC
_TEXT_EXTENSIONS = {
    ".rb", ".js", ".py", ".c", ".cpp", ".h", ".txt", ".xml", ".html",
    ".css", ".json", ".yaml", ".yml", ".lua", ".pl", ".php", ".java",
    ".md", ".csv", ".ini", ".cfg", ".conf", ".smt2", ".smt", ".asm",
    ".s", ".rs", ".go", ".swift", ".ts",
}

# File extensions that are script-type PoC (executed via shell)
_SCRIPT_EXTENSIONS = {".sh", ".bash"}

# File extensions known to be binary
_BINARY_EXTENSIONS = {
    ".mp4", ".avi", ".mkv", ".mov", ".tiff", ".tif", ".bmp", ".gif",
    ".png", ".jpg", ".jpeg", ".webp", ".ico", ".pdf", ".doc", ".dwg",
    ".dxf", ".eps", ".ps", ".svg", ".wav", ".mp3", ".flac", ".ogg",
    ".zip", ".gz", ".bz2", ".tar", ".rar", ".7z", ".bin", ".dat",
    ".pcap", ".elf", ".wasm", ".o", ".so", ".a",
}


def _infer_poc_type(poc_path: str) -> str:
    """Infer PoC type from file extension."""
    lower = poc_path.lower()
    for ext in _SCRIPT_EXTENSIONS:
        if lower.endswith(ext):
            return "script"
    for ext in _TEXT_EXTENSIONS:
        if lower.endswith(ext):
            return "text"
    for ext in _BINARY_EXTENSIONS:
        if lower.endswith(ext):
            return "binary"
    # Default to binary for unknown extensions
    return "binary"


def parse_repro_command(secb_sh: str) -> ReproCommand:
    """Extract repro command structure from secb_sh content.

    Parses the repro() function body in the secb_sh script to extract
    the binary path, arguments, and PoC file path.
    """
    # Extract the repro() function body
    repro_match = re.search(
        r'repro\s*\(\)\s*\{(.*?)\}', secb_sh, re.DOTALL
    )
    if not repro_match:
        # Fallback: try to find any command with /testcase/
        return _fallback_parse(secb_sh)

    body = repro_match.group(1)

    # Filter out comments, echo, empty lines, local, return statements
    lines = []
    for line in body.strip().splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        if stripped.startswith("echo "):
            continue
        if stripped.startswith("local "):
            continue
        if stripped.startswith("return"):
            continue
        if stripped.startswith("cd "):
            continue
        lines.append(stripped)

    if not lines:
        return _fallback_parse(secb_sh)

    # Take the main command line (usually the last substantive line,
    # or the one containing /testcase/)
    cmd_line = None
    for line in lines:
        if "/testcase/" in line:
            cmd_line = line
            break
    if cmd_line is None:
        cmd_line = lines[-1]

    return _parse_command_line(cmd_line)


def _fallback_parse(secb_sh: str) -> ReproCommand:
    """Fallback parser when repro() function isn't found cleanly."""
    # Look for any line referencing /testcase/
    for line in secb_sh.splitlines():
        stripped = line.strip()
        if "/testcase/" in stripped and not stripped.startswith("#"):
            return _parse_command_line(stripped)

    # Last resort: return a minimal command
    return ReproCommand(
        binary="",
        args="",
        poc_path="/testcase/poc",
        poc_type="binary",
    )


def _parse_command_line(cmd_line: str) -> ReproCommand:
    """Parse a single command line into ReproCommand components."""
    # Remove shell redirections (2>&1, >/dev/null, etc.)
    cmd_line = re.sub(r'\d*>[>&]*\s*\S+', '', cmd_line)
    # Remove trailing pipe commands
    cmd_line = re.sub(r'\|.*$', '', cmd_line)
    # Remove shell variable expansions like $TIMEOUT_CMD
    cmd_line = re.sub(r'\$\w+\s*', '', cmd_line)
    # Remove timeout command prefix
    cmd_line = re.sub(r'timeout\s+\d+\s*', '', cmd_line)
    cmd_line = cmd_line.strip()

    # Split into tokens
    tokens = cmd_line.split()
    if not tokens:
        return ReproCommand(binary="", args="", poc_path="/testcase/poc", poc_type="binary")

    binary = tokens[0]
    args_parts = []
    poc_path = ""

    for token in tokens[1:]:
        if "/testcase/" in token:
            poc_path = token
        else:
            args_parts.append(token)

    # If no explicit poc_path found, check if last arg looks like a file path
    if not poc_path and args_parts:
        last = args_parts[-1]
        if "/" in last and not last.startswith("-"):
            poc_path = last
            args_parts = args_parts[:-1]

    if not poc_path:
        poc_path = "/testcase/poc"

    poc_type = _infer_poc_type(poc_path)
    args = " ".join(args_parts)

    # Build a command template preserving original token order
    cmd_template = cmd_line.replace(poc_path, "{poc}")

    return ReproCommand(
        binary=binary,
        args=args,
        poc_path=poc_path,
        poc_type=poc_type,
        cmd_template=cmd_template,
    )
