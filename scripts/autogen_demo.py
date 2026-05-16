"""
AutoGen 核心组件使用示例 —— 基于 secbench-solver 项目的组件演示

本示例展示 secbench-solver 漏洞修复系统中实际使用的 4 个 AutoGen 核心组件：
  1. OpenAIChatCompletionClient  — LLM 模型客户端
  2. FunctionTool                — 将 Python 函数包装为 Agent 可调用的工具
  3. AssistantAgent              — LLM 驱动的智能体（支持工具调用、系统提示词）
  4. ToolCallRequestEvent        — 从对话轨迹中提取工具调用信息

运行方式:
  pip install autogen-agentchat autogen-ext[openai]
  python autogen_demo.py
"""

import asyncio
import json

# ============================================================================
# 组件 1: OpenAIChatCompletionClient — 模型客户端
# ============================================================================
# 作用: 封装 OpenAI 兼容 API 的调用，支持 function calling、流式输出等
# 在 secbench-solver 中: agents.py 的 create_model_client() 用它连接 LLM

from autogen_ext.models.openai import OpenAIChatCompletionClient

model_client = OpenAIChatCompletionClient(
    model="gpt-4o-mini",                          # 模型名称
    base_url="https://api.openai.com/v1",          # API 端点（兼容 OpenAI 协议的都行）
    api_key="sk-your-api-key",                     # API 密钥
    model_info={                                    # 模型能力声明
        "vision": False,
        "function_calling": True,                   # 关键：必须支持 function calling
        "json_output": True,
        "family": "unknown",
        "structured_output": True,
    },
)


# ============================================================================
# 组件 2: FunctionTool — 将 Python 函数包装为 Agent 工具
# ============================================================================
# 作用: 把普通 Python 函数变成 Agent 可以通过 function calling 调用的工具
# 在 secbench-solver 中: tools.py 用它创建 bash 和 str_replace_edit 两个工具
#   - bash 工具: 在 Docker 容器内执行命令
#   - str_replace_edit 工具: 精确替换容器内文件的文本

from autogen_core.tools import FunctionTool

# --- 示例工具 1: 文件读取 ---
def read_source_file(file_path: str) -> str:
    """读取指定路径的源代码文件内容。

    Args:
        file_path: 要读取的文件路径。

    Returns:
        文件内容（带行号）。
    """
    # 实际项目中这里是 docker exec cat -n <path>
    # 这里用本地文件模拟
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
        return "\n".join(f"{i+1:>4} | {line.rstrip()}" for i, line in enumerate(lines))
    except FileNotFoundError:
        return f"Error: 文件 {file_path} 不存在"

# --- 示例工具 2: 代码搜索 ---
def search_code(pattern: str, directory: str = ".") -> str:
    """在指定目录中搜索匹配模式的代码行。

    Args:
        pattern: 要搜索的文本模式。
        directory: 搜索的目录路径，默认为当前目录。

    Returns:
        匹配的文件和行。
    """
    import subprocess
    try:
        result = subprocess.run(
            ["grep", "-rn", pattern, directory, "--include=*.py"],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout[:3000] if result.stdout else f"未找到匹配 '{pattern}' 的内容"
    except Exception as e:
        return f"搜索出错: {e}"

# 用 FunctionTool 包装 —— AutoGen 会自动从函数签名和 docstring 生成 JSON Schema
# Agent 在对话中可以通过 function calling 调用这些工具
read_tool = FunctionTool(
    read_source_file,
    description="读取源代码文件内容，返回带行号的文本。用于分析代码。",
)

search_tool = FunctionTool(
    search_code,
    description="在目录中搜索代码模式，返回匹配的文件和行号。",
)

# FunctionTool 自动生成的 JSON Schema（这就是发给 LLM 的工具描述）
print("=== FunctionTool 自动生成的工具 Schema ===")
print(json.dumps(read_tool.schema, indent=2, ensure_ascii=False))
print()


# ============================================================================
# 组件 3: AssistantAgent — LLM 驱动的智能体
# ============================================================================
# 作用: 核心智能体类，接收任务 → 调用 LLM → 使用工具 → 返回结果
# 在 secbench-solver 中: agents.py 用它创建 4 个角色不同的 Agent
#   - Mutator:  生成 PoC 变体（只有 bash 工具）
#   - Analyzer: 差分分析 + 动态探针（bash + str_replace_edit 工具）
#   - Patcher:  修复漏洞（bash + str_replace_edit 工具）
#   - Selector: 选择最优补丁（无工具，纯推理）

from autogen_agentchat.agents import AssistantAgent

# --- 创建一个代码分析 Agent（模拟 secbench-solver 的 Analyzer 角色）---
analyzer = AssistantAgent(
    name="CodeAnalyzer",                    # Agent 名称（用于日志和轨迹记录）
    model_client=model_client,              # 绑定的 LLM 客户端
    tools=[read_tool, search_tool],         # 可用工具列表
    system_message="""\
你是一个代码安全分析专家。

## 你的工具
- read_source_file: 读取源代码文件
- search_code: 搜索代码模式

## 你的任务
分析给定的代码，找出潜在的安全问题，输出结构化的分析报告。

## 输出格式
```
# 安全分析报告

## 问题 1
- 位置: <文件:行号>
- 类型: <问题类型>
- 严重程度: HIGH | MEDIUM | LOW
- 描述: <问题描述>
- 建议: <修复建议>
```
""",
    description="分析代码中的安全问题并生成结构化报告。",
    max_tool_iterations=10,                 # 最大工具调用轮数（防止无限循环）
    reflect_on_tool_use=True,               # 每次工具调用后让 LLM 反思结果
)

# --- 创建一个纯推理 Agent（模拟 secbench-solver 的 Selector 角色）---
selector = AssistantAgent(
    name="PatchSelector",
    model_client=model_client,
    # 注意: Selector 没有工具，只做纯文本推理
    system_message="""\
你是一个补丁评估专家。从多个候选补丁中选择最优的一个。
评估标准（优先级从高到低）：
1. 鲁棒性：修复是否覆盖所有触发路径
2. 根因正确性：是否修复了根本原因而非表面症状
3. 最小化：补丁是否足够精简
4. 安全性：是否引入新问题

输出格式:
SELECTED: <编号>
REASON: <理由>
""",
    description="评估并选择最优补丁。",
)


# ============================================================================
# 组件 4: ToolCallRequestEvent — 从对话轨迹提取工具调用
# ============================================================================
# 作用: 表示 Agent 发出的工具调用请求消息
# 在 secbench-solver 中: pipeline.py 的 _extract_mutator_trace() 用它
#   从 Mutator 的对话历史中提取所有 bash 命令，记录变异操作轨迹

from autogen_agentchat.messages import ToolCallRequestEvent


# ============================================================================
# 完整运行示例: Agent 执行任务 → 提取轨迹
# ============================================================================

async def demo_run():
    """演示 Agent 执行任务并提取工具调用轨迹的完整流程。"""

    # --- 1. 让 Analyzer Agent 执行一个分析任务 ---
    print("\n" + "=" * 60)
    print("运行 CodeAnalyzer Agent...")
    print("=" * 60)

    # agent.run() 是核心调用方式
    # 在 secbench-solver 中:
    #   mutator.run(task=...)   → 生成 PoC 变体
    #   analyzer.run(task=...)  → 差分属性分析
    #   patcher.run(task=...)   → 修复漏洞
    #   selector.run(task=...)  → 选择最优补丁
    result = await analyzer.run(
        task="请分析 ./autogen_demo.py 这个文件，找出其中的安全问题。"
    )

    # --- 2. 打印 Agent 的最终回复 ---
    print("\n--- Agent 最终回复 ---")
    if result.messages:
        last_msg = result.messages[-1]
        content = last_msg.content if isinstance(last_msg.content, str) else str(last_msg.content)
        print(content[:2000])

    # --- 3. 从对话轨迹中提取工具调用（对应 secbench-solver 的轨迹分析）---
    print("\n--- 工具调用轨迹 ---")
    tool_calls_log = []
    for msg in result.messages:
        # ToolCallRequestEvent 表示 Agent 请求调用工具
        if isinstance(msg, ToolCallRequestEvent):
            for fc in msg.content:
                tool_name = getattr(fc, "name", "unknown")
                arguments = getattr(fc, "arguments", "")
                tool_calls_log.append({
                    "tool": tool_name,
                    "arguments": arguments,
                })
                print(f"  调用工具: {tool_name}")
                print(f"  参数: {arguments[:200]}")
                print()

    print(f"共调用了 {len(tool_calls_log)} 次工具")

    # --- 4. 演示 Selector（纯推理，无工具调用）---
    print("\n" + "=" * 60)
    print("运行 PatchSelector Agent（纯推理，无工具）...")
    print("=" * 60)

    selector_result = await selector.run(
        task="""\
从以下 2 个候选补丁中选择最优的：

### 候选 1
```diff
- if (index >= size) return;
+ if (index >= size) { log_error("bounds"); return NULL; }
```
变体测试: 3/3 通过

### 候选 2
```diff
- data = buffer[index];
+ if (index < size) data = buffer[index]; else data = 0;
```
变体测试: 2/3 通过（1 个仍崩溃）
"""
    )

    if selector_result.messages:
        print(selector_result.messages[-1].content)

    return result, selector_result


# ============================================================================
# secbench-solver 的编排模式说明
# ============================================================================
#
# secbench-solver 没有使用 AutoGen 的 GroupChat/Team 机制，
# 而是在 pipeline.py 中手动编排 Agent 的执行顺序：
#
#   for round in range(MAX_ROUNDS):          # 最多 3 轮对抗循环
#       # Step 1: Mutator 生成 PoC 变体
#       result = await mutator.run(task=...)
#       crash_reports = collect_variants()    # 门控: 需要崩溃+不崩溃两类
#
#       # Step 2: Analyzer 差分分析（跨轮复用，保留记忆）
#       result = await analyzer.run(task=...)
#       property_report = extract_report()
#       reset_source()                        # 清理探针代码
#
#       # Step 3: Patcher 并行修复（多个容器，高温度采样）
#       results = await asyncio.gather(
#           patcher_0.run(task=...),           # 容器 A
#           patcher_1.run(task=...),           # 容器 B
#       )
#       # 门控: 空 diff → 重试, 编译失败 → 重试, 验证失败 → 下一轮
#
#       # Step 4: 验证 + 变体鲁棒性测试
#       if perfect_patch_found:
#           break
#
#   # Stage 2: Selector 选最优
#   best = await selector.run(task=...)
#
# 这种手动编排的优势:
#   - 每个阶段有精确的门控逻辑（差分验证、编译验证、PoC 验证）
#   - 支持闭环反馈（失败补丁 → 下一轮的上下文）
#   - Analyzer 跨轮复用（保留对话记忆，增量更新分析）
#   - Patcher 并行执行（asyncio.gather + 独立 Docker 容器）
#   - 灵活的重试策略（同轮重试 vs 跨轮反馈）


if __name__ == "__main__":
    print("SecBench-Solver AutoGen 组件使用演示")
    print("=" * 60)
    print()
    print("本项目使用的 AutoGen 组件:")
    print("  1. OpenAIChatCompletionClient — LLM 模型客户端")
    print("  2. FunctionTool              — Python 函数 → Agent 工具")
    print("  3. AssistantAgent            — LLM 智能体（工具调用 + 系统提示词）")
    print("  4. ToolCallRequestEvent      — 对话轨迹中的工具调用事件")
    print()

    # 如果有有效的 API key，取消下面的注释运行完整演示
    # asyncio.run(demo_run())

    # 没有 API key 时，只展示静态信息
    print("=== Agent 配置展示 ===")
    print(f"Analyzer Agent: name={analyzer.name}, tools={[t.name for t in analyzer._tools]}")
    print(f"Selector Agent: name={selector.name}, tools=[] (纯推理)")
    print()
    print("=== 工具 Schema（发送给 LLM 的工具描述）===")
    print(json.dumps(read_tool.schema, indent=2, ensure_ascii=False))
