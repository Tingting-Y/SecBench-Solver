"""Trajectory serialization for SEC-bench solver.

Converts AutoGen agent conversation messages into OpenAI API format
and saves them incrementally to JSON files for debugging and research.
"""

from __future__ import annotations

import json
import logging
import os

from autogen_agentchat.messages import (
    TextMessage,
    ThoughtEvent,
    ToolCallExecutionEvent,
    ToolCallRequestEvent,
    ToolCallSummaryMessage,
)

logger = logging.getLogger(__name__)


def _serialize_function_call(fc) -> dict:
    """Serialize a FunctionCall to OpenAI tool_calls format."""
    return {
        "id": fc.id,
        "type": "function",
        "function": {
            "name": fc.name,
            "arguments": fc.arguments,
        },
    }


def _serialize_function_result(fr) -> dict:
    """Serialize a FunctionExecutionResult to OpenAI tool message format."""
    return {
        "role": "tool",
        "content": fr.content,
        "tool_call_id": fr.call_id,
        "name": fr.name,
    }


def serialize_messages(messages) -> list[dict]:
    """Convert AutoGen result.messages to OpenAI API message format.

    Mapping:
      TextMessage (first/user task)    -> role: "user"
      TextMessage (agent response)     -> role: "assistant"
      ToolCallRequestEvent             -> role: "assistant", tool_calls: [...]
      ToolCallExecutionEvent           -> one "tool" message per result
      ToolCallSummaryMessage           -> role: "assistant" with content + tool_calls + results
      ThoughtEvent                     -> role: "assistant", thought: true
      Other                            -> role: "system", content: str(msg)
    """
    serialized: list[dict] = []
    seen_first_text = False

    for msg in messages:
        # Extract token usage if available
        usage = None
        if hasattr(msg, "models_usage") and msg.models_usage is not None:
            usage = {
                "prompt_tokens": msg.models_usage.prompt_tokens,
                "completion_tokens": msg.models_usage.completion_tokens,
            }

        if isinstance(msg, ToolCallRequestEvent):
            entry = {
                "role": "assistant",
                "content": None,
                "tool_calls": [_serialize_function_call(fc) for fc in msg.content],
                "source": msg.source,
            }
            if usage:
                entry["usage"] = usage
            serialized.append(entry)

        elif isinstance(msg, ToolCallExecutionEvent):
            for fr in msg.content:
                entry = _serialize_function_result(fr)
                entry["source"] = msg.source
                serialized.append(entry)

        elif isinstance(msg, ToolCallSummaryMessage):
            serialized.append({
                "role": "assistant",
                "content": msg.content,
                "tool_calls": [_serialize_function_call(fc) for fc in msg.tool_calls],
                "results": [
                    {"content": fr.content, "call_id": fr.call_id, "name": fr.name}
                    for fr in msg.results
                ],
                "source": msg.source,
            })

        elif isinstance(msg, ThoughtEvent):
            entry = {
                "role": "assistant",
                "content": msg.content,
                "thought": True,
                "source": msg.source,
            }
            if usage:
                entry["usage"] = usage
            serialized.append(entry)

        elif isinstance(msg, TextMessage):
            # First TextMessage is typically the user task
            if not seen_first_text:
                role = "user"
                seen_first_text = True
            else:
                role = "assistant"
            entry = {
                "role": role,
                "content": msg.content,
                "source": msg.source,
            }
            if usage:
                entry["usage"] = usage
            serialized.append(entry)

        else:
            # Fallback for unknown message types
            content = getattr(msg, "content", None)
            if content is not None:
                if isinstance(content, str):
                    text = content
                else:
                    text = str(content)
            else:
                text = str(msg)
            serialized.append({
                "role": "system",
                "content": text,
                "type": type(msg).__name__,
                "source": getattr(msg, "source", "unknown"),
            })

    return serialized


def init_trajectory(traj_path: str, instance_id: str) -> None:
    """Initialize a trajectory file with metadata."""
    data = {
        "instance_id": instance_id,
        "agents": {},
    }
    os.makedirs(os.path.dirname(traj_path) or ".", exist_ok=True)
    with open(traj_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logger.info("Initialized trajectory file: %s", traj_path)


def append_agent_trajectory(traj_path: str, agent_key: str, messages) -> None:
    """Incrementally append one agent's trajectory to the JSON file.

    Reads the existing file, adds the serialized messages under
    agents[agent_key], and writes it back. This ensures data is
    persisted even if the process crashes later.
    """
    serialized = serialize_messages(messages)

    try:
        with open(traj_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {"agents": {}}

    data["agents"][agent_key] = serialized

    with open(traj_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logger.info(
        "Saved trajectory for %s: %d messages -> %s",
        agent_key, len(serialized), traj_path,
    )


def summarize_token_usage(traj_path: str) -> dict:
    """Summarize token usage from a trajectory file.

    Returns dict with per-agent and total token counts:
    {
        "agents": {"mutator_r0": {"prompt_tokens": ..., "completion_tokens": ...}, ...},
        "total_prompt_tokens": ...,
        "total_completion_tokens": ...,
        "total_tokens": ...,
    }
    """
    try:
        with open(traj_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"agents": {}, "total_prompt_tokens": 0, "total_completion_tokens": 0, "total_tokens": 0}

    agent_usage: dict[str, dict[str, int]] = {}
    total_prompt = 0
    total_completion = 0

    for agent_key, messages in data.get("agents", {}).items():
        ap, ac = 0, 0
        for msg in messages:
            u = msg.get("usage")
            if u:
                ap += u.get("prompt_tokens", 0)
                ac += u.get("completion_tokens", 0)
        agent_usage[agent_key] = {"prompt_tokens": ap, "completion_tokens": ac}
        total_prompt += ap
        total_completion += ac

    return {
        "agents": agent_usage,
        "total_prompt_tokens": total_prompt,
        "total_completion_tokens": total_completion,
        "total_tokens": total_prompt + total_completion,
    }
