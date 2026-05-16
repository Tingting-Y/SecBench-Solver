"""Tool factory functions for SEC-bench solver agents.

Each factory takes a container_id and returns an AutoGen FunctionTool
bound to that container via closure.

Tools:
  - bash:             Execute arbitrary commands inside the container.
  - str_replace_edit: Precise text replacement in container files.
"""

from __future__ import annotations

import logging

from autogen_core.tools import FunctionTool

from config import MAX_OUTPUT_LENGTH
from docker_tools import exec_cmd, read_file, write_file

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# bash tool
# ---------------------------------------------------------------------------


def make_bash_tool(container_id: str) -> FunctionTool:
    """Create a bash execution tool bound to a specific container."""

    def bash(command: str) -> str:
        """Execute a bash command inside the container.

        Returns the exit code followed by combined stdout and stderr.
        Use this for: running programs, reading files (cat -n), searching
        code (rg), listing directories (ls/find), creating files via
        heredoc, running Python scripts, etc.

        Args:
            command: The bash command to execute.

        Returns:
            A string containing the exit code and command output.
        """
        exit_code, stdout, stderr = exec_cmd(container_id, command)
        combined = stdout
        if stderr:
            combined = combined + "\n" + stderr if combined else stderr
        result = f"[exit code: {exit_code}]\n{combined}"
        # Truncate overly long output, keeping head and tail
        if len(result) > MAX_OUTPUT_LENGTH:
            half = MAX_OUTPUT_LENGTH // 2
            result = result[:half] + "\n\n... [output truncated] ...\n\n" + result[-half:]
        return result

    return FunctionTool(
        bash,
        description=(
            "Execute a bash command in the container and return exit code + output. "
            "Available tools inside: cat, rg (ripgrep), find, ls, python3, git. "
            "For file creation use heredoc: cat > path << 'EOF'\\ncontent\\nEOF"
        ),
    )


# ---------------------------------------------------------------------------
# str_replace_edit tool
# ---------------------------------------------------------------------------

_SNIPPET_CONTEXT = 4  # lines of context to show around the edit


def make_str_replace_tool(container_id: str) -> FunctionTool:
    """Create a str_replace editing tool bound to a specific container."""

    def str_replace_edit(file_path: str, old_str: str, new_str: str) -> str:
        """Replace old_str with new_str in a file inside the container.

        old_str must appear exactly once in the file.  Include enough
        surrounding context lines to make old_str unique.

        Args:
            file_path: Absolute path to the file in the container.
            old_str:   The exact text to find (must be unique in the file).
            new_str:   The replacement text.

        Returns:
            Success message with a snippet, or an error description.
        """
        try:
            file_content = read_file(container_id, file_path)
        except FileNotFoundError as exc:
            return f"Error: {exc}"

        # --- validate uniqueness (direct match, no tab expansion) ---
        occurrences = file_content.count(old_str)
        if occurrences == 0:
            return (
                f"Error: old_str not found verbatim in {file_path}. "
                "Read the file first with bash('cat -n <path>') and "
                "copy the exact text including whitespace and tabs."
            )
        if occurrences > 1:
            lines: list[str] = []
            pos = 0
            for _ in range(occurrences):
                idx = file_content.find(old_str, pos)
                line_num = file_content.count("\n", 0, idx) + 1
                lines.append(str(line_num))
                pos = idx + len(old_str)
            return (
                f"Error: old_str appears {occurrences} times in {file_path} "
                f"(at lines {', '.join(lines)}). "
                "Include more surrounding context to make it unique."
            )

        # --- perform replacement directly (preserves original formatting) ---
        updated = file_content.replace(old_str, new_str, 1)
        write_file(container_id, file_path, updated)

        # --- build confirmation snippet (expand tabs for display only) ---
        display_content = updated.expandtabs()
        display_lines = display_content.splitlines()
        replace_start = file_content.find(old_str)
        start_line = file_content.count("\n", 0, replace_start)
        snippet_start = max(0, start_line - _SNIPPET_CONTEXT)
        snippet_end = min(
            len(display_lines),
            start_line + new_str.count("\n") + 1 + _SNIPPET_CONTEXT,
        )
        snippet_lines = [
            f"{i + 1:>6}\t{display_lines[i]}"
            for i in range(snippet_start, snippet_end)
        ]
        snippet = "\n".join(snippet_lines)
        return (
            f"Successfully edited {file_path}. Snippet around the change:\n"
            f"{snippet}\n"
            "Review the changes and make further edits if needed."
        )

    return FunctionTool(
        str_replace_edit,
        description=(
            "Replace exact text in a container file. old_str must appear "
            "exactly once (include surrounding lines for uniqueness). "
            "Use bash('cat -n <path>') to read the file first."
        ),
    )
