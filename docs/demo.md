# SecBench-Solver AutoGen 组件使用说明

## 项目简介

SecBench-Solver 是一个基于 AutoGen 多智能体框架的 C/C++ 内存安全漏洞自动修复系统。系统通过 4 个专职 Agent 组成对抗式流水线，实现"变异 → 分析 → 修复 → 验证"的闭环工作流。

```
崩溃报告 ──Mutator──> PoC 变体群（崩溃 + 不崩溃）
                       │
                 差分对比（什么输入崩溃，什么不崩溃？）
                       │
                   Analyzer ──> 安全属性（根因条件）
                       │
                   Patcher  ──> 定向修复（基于属性，不是盲猜）
                       │
                 原始 PoC + 全部变体验证
                       │
                       ──反馈──> 下一轮对抗
```

---

## AutoGen 框架概述

[AutoGen](https://github.com/microsoft/autogen) 是微软开源的多智能体编排框架（Python，约 11.2 万行源码），提供：

- Agent 抽象（LLM 驱动的智能体，支持工具调用）
- 模型客户端（对接 OpenAI、Anthropic、本地模型等）
- 工具系统（将 Python 函数自动转为 LLM function calling 格式）
- 团队编排（轮询、选择器、图工作流等多种模式）

本项目使用了其中 **4 个核心组件**，它们之间的交互关系如下。

---

## 四个组件的交互关系

### 组件依赖全景图

```
┌─────────────────────────────────────────────────────────────────┐
│                        pipeline.py（编排层）                      │
│                                                                  │
│  for round in range(3):                                          │
│      result = await mutator.run(task=...)   ◄─── 返回 TaskResult │
│      result = await analyzer.run(task=...)                       │
│      result = await patcher.run(task=...)                        │
│                         │                                        │
│                         ▼                                        │
│              result.messages ──── 遍历提取 ToolCallRequestEvent  │
│                                  记录工具调用轨迹                  │
└──────────────────────────┬──────────────────────────────────────┘
                           │ 创建 Agent
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                  AssistantAgent（智能体）                         │
│                                                                  │
│  构造参数:                                                        │
│    ├── model_client ──────► OpenAIChatCompletionClient            │
│    ├── tools ─────────────► [FunctionTool, FunctionTool, ...]    │
│    └── system_message ────► 角色提示词（决定 Agent 行为）          │
│                                                                  │
│  agent.run(task) 内部循环:                                        │
│    1. 将 system_message + task + 历史消息 发送给 model_client     │
│    2. model_client 调用 LLM API，返回回复                         │
│    3. 如果回复包含 tool_calls:                                    │
│       a. 根据 tool name 找到对应的 FunctionTool                   │
│       b. 用 tool arguments 调用 FunctionTool.run()               │
│       c. 将工具返回值作为 tool_result 追加到消息历史               │
│       d. 产生 ToolCallRequestEvent（记录到 result.messages）      │
│       e. 回到步骤 1，继续下一轮                                   │
│    4. 如果回复是纯文本 → 结束，返回 TaskResult                    │
└─────────────────────────────────────────────────────────────────┘
```

### 组件绑定关系


```
                    ┌─────────────────────────┐
                    │  OpenAIChatCompletion    │
                    │  Client                  │
                    │  （连接 LLM API）         │
                    └────────┬────────────────┘
                             │ 注入为 model_client
                             ▼
┌──────────────┐    ┌─────────────────────────┐
│ FunctionTool │───►│                         │
│  (bash)      │    │    AssistantAgent        │     调用 agent.run(task)
├──────────────┤───►│                         │─────────────────────────►  TaskResult
│ FunctionTool │    │  （组装大脑+手+角色）     │                            │
│  (edit)      │    └─────────────────────────┘                            │
└──────────────┘                                                           ▼
  注入为 tools                                                    result.messages 中包含
                                                                  ToolCallRequestEvent
                                                                  （记录了每次工具调用）
```

用代码表达就是：

```python
# 第一步：创建"大脑" —— 模型客户端
client = OpenAIChatCompletionClient(model="gpt-5-mini", api_key="...")

# 第二步：创建"手" —— 工具（通过闭包绑定到 Docker 容器）
bash_tool = FunctionTool(bash_func, description="...")   # 闭包捕获了 container_id
edit_tool = FunctionTool(edit_func, description="...")   # 同一个容器

# 第三步：组装"人" —— 把大脑、手、角色定义绑在一起
patcher = AssistantAgent(
    model_client=client,          # ← 绑定大脑
    tools=[bash_tool, edit_tool], # ← 绑定手
    system_message="你是漏洞修复专家...",  # ← 绑定角色
)

# 第四步：让这个人干活
result = await patcher.run(task="修复这个漏洞...")

# 第五步：查看行动日记 —— 提取 ToolCallRequestEvent
for msg in result.messages:
    if isinstance(msg, ToolCallRequestEvent):
        print(msg.content)  # 记录了调用了什么工具、传了什么参数
```

### agent.run() 内部发生了什么

`AssistantAgent.run(task)` 是整个系统的核心驱动循环。它内部做的事情就是不断在"想"和"做"之间切换：

```
                        ┌──────────────────────────────────────┐
                        │          agent.run(task)             │
                        └──────────────┬───────────────────────┘
                                       │
                                       ▼
                        ┌──────────────────────────────────────┐
                   ┌───►│  把 system_message + task + 历史消息  │
                   │    │  + 工具 Schema 一起发给 model_client  │
                   │    └──────────────┬───────────────────────┘
                   │                   │
                   │                   ▼  model_client 调用 LLM API
                   │    ┌──────────────────────────────────────┐
                   │    │         LLM 返回什么？                │
                   │    └───────┬──────────────────┬───────────┘
                   │            │                  │
                   │       返回工具调用          返回纯文本
                   │       (tool_call)          (最终回答)
                   │            │                  │
                   │            ▼                  ▼
                   │    ┌───────────────┐  ┌──────────────────┐
                   │    │ 找到对应的     │  │  结束循环         │
                   │    │ FunctionTool   │  │  返回 TaskResult  │
                   │    │ 执行它         │  │  (含所有消息历史)  │
                   │    │               │  └──────────────────┘
                   │    │ 产生一条       │
                   │    │ ToolCallRequest│
                   │    │ Event 记录     │
                   │    └───────┬───────┘
                   │            │
                   │            │ 工具结果追加到消息历史
                   └────────────┘ 进入下一轮
```

**具体例子**：Patcher 修复一个 heap-buffer-overflow

| 轮次 | LLM 的决策 | 调用的工具 | 工具做了什么 |
|:----:|-----------|-----------|------------|
| 1 | "我先看看崩溃位置的源码" | `bash("cat -n /src/parser.c")` | 在容器内执行命令，返回源码 |
| 2 | "第 42 行缺少边界检查，我来修" | `str_replace_edit("/src/parser.c", old, new)` | 在容器内替换文件内容 |
| 3 | "修复完成，添加了 index < size 检查" | （无工具调用，纯文本） | 循环结束，返回结果 |

每一轮的工具调用都会产生一个 `ToolCallRequestEvent`，pipeline.py 事后可以遍历这些事件来分析 Agent 做了什么。

### 闭包绑定：同一个工具函数，不同的容器

本项目的一个关键设计是用 Python 闭包让同一个工具定义绑定到不同的 Docker 容器：

```python
# tools.py 中的工厂函数
def make_bash_tool(container_id: str) -> FunctionTool:
    def bash(command: str) -> str:          # ← 闭包：捕获了外层的 container_id
        exit_code, stdout, stderr = exec_cmd(container_id, command)
        return f"[exit code: {exit_code}]\n{stdout}"
    return FunctionTool(bash, description="...")

# 使用时：同一个函数逻辑，绑定到不同容器
tool_for_container_A = make_bash_tool("container_A")  # bash 命令跑在容器 A
tool_for_container_B = make_bash_tool("container_B")  # bash 命令跑在容器 B

# 并行 Patcher 各自操作自己的容器，互不干扰
patcher_0 = AssistantAgent(tools=[tool_for_container_A], ...)
patcher_1 = AssistantAgent(tools=[tool_for_container_B], ...)
```

这就是为什么多个 Patcher 可以并行修复而互不干扰——每个 Patcher 的工具绑定了独立的容器。

---

## 组件 1：OpenAIChatCompletionClient（模型客户端）

**来源**：`autogen_ext.models.openai`

**作用**：封装 OpenAI 兼容 API 的调用，处理 function calling、token 计数、流式输出等底层细节。

**在本项目中的使用**（`agents.py:31-51`）：

```python
from autogen_ext.models.openai import OpenAIChatCompletionClient

def create_model_client(temperature=None):
    return OpenAIChatCompletionClient(
        model="gpt-5-mini",                        # 模型名称
        base_url="https://api.chatanywhere.tech/v1", # API 端点
        api_key="",                            # API 密钥
        model_info={
            "vision": False,
            "function_calling": True,   # 必须支持 function calling
            "json_output": True,
            "family": "unknown",
            "structured_output": True,
        },
        temperature=temperature,        # Patcher 用高温度(1.0)增加多样性
    )
```

**关键点**：
- 兼容所有 OpenAI 协议的 API（OpenAI、Azure、本地部署等）
- `model_info` 声明模型能力，框架据此决定是否启用 function calling
- Patcher 使用 `temperature=1.0` 做多样性采样，多个 Patcher 并行生成不同补丁

---

## 组件 2：FunctionTool（工具包装器）

**来源**：`autogen_core.tools`

**作用**：将普通 Python 函数自动转换为 Agent 可通过 function calling 调用的工具。AutoGen 会从函数签名和 docstring 自动生成 JSON Schema。

**在本项目中的使用**（`tools.py`）：

本项目定义了 2 个工具，通过闭包绑定到特定的 Docker 容器：

### 工具 1：bash（命令执行）

```python
from autogen_core.tools import FunctionTool

def make_bash_tool(container_id: str) -> FunctionTool:
    def bash(command: str) -> str:
        """Execute a bash command inside the container."""
        exit_code, stdout, stderr = exec_cmd(container_id, command)
        return f"[exit code: {exit_code}]\n{stdout}\n{stderr}"

    return FunctionTool(
        bash,
        description="Execute a bash command in the container...",
    )
```

### 工具 2：str_replace_edit（精确文本替换）

```python
def make_str_replace_tool(container_id: str) -> FunctionTool:
    def str_replace_edit(file_path: str, old_str: str, new_str: str) -> str:
        """Replace old_str with new_str in a file inside the container.
        old_str must appear exactly once in the file."""
        content = read_file(container_id, file_path)
        # 唯一性校验：出现 0 次或多次都报错
        if content.count(old_str) != 1:
            return "Error: old_str not unique..."
        updated = content.replace(old_str, new_str, 1)
        write_file(container_id, file_path, updated)
        return "Successfully edited..."

    return FunctionTool(str_replace_edit, description="...")
```

**关键设计**：
- **闭包绑定容器**：`make_bash_tool(container_id)` 返回的工具自动绑定到指定容器，Agent 调用时无需关心容器 ID
- **自动 Schema 生成**：FunctionTool 从函数的参数类型注解和 docstring 自动生成 JSON Schema，LLM 据此构造工具调用参数
- **唯一性校验**：str_replace_edit 要求 old_str 在文件中只出现一次，避免误改

各 Agent 的工具分配：

| Agent | bash | str_replace_edit | 说明 |
|-------|:----:|:----------------:|------|
| Mutator | ✓ | ✗ | 只需执行命令生成变体 |
| Analyzer | ✓ | ✓ | 读源码 + 插入动态探针 |
| Patcher | ✓ | ✓ | 读源码 + 编辑修复 |
| Selector | ✗ | ✗ | 纯推理，不需要工具 |

---

## 组件 3：AssistantAgent（LLM 智能体）

**来源**：`autogen_agentchat.agents`

**作用**：AutoGen 的核心智能体类。接收任务消息 → 调用 LLM 生成回复 → 如果 LLM 返回工具调用则执行工具 → 将工具结果反馈给 LLM → 循环直到 LLM 给出最终回复。

**在本项目中的使用**（`agents.py:368-488`）：

```python
from autogen_agentchat.agents import AssistantAgent

# 创建 Mutator Agent
mutator = AssistantAgent(
    name="Mutator",                          # Agent 名称
    model_client=model_client,               # LLM 客户端
    tools=[bash_tool],                       # 可用工具
    system_message="You are a vulnerability exploitation expert...",
    description="Generates PoC variants...",
    max_tool_iterations=30,                  # 最大工具调用轮数
    reflect_on_tool_use=True,                # 每次工具调用后反思
)

# 执行任务（异步调用）
result = await mutator.run(task="Generate 3 PoC variants...")
```

**本项目的 4 个 Agent**：

| Agent | 系统提示词要点 | 工具迭代上限 | 特殊说明 |
|-------|--------------|:-----------:|---------|
| **Mutator** | PoC 变异专家，生成崩溃+不崩溃变体 | 30 | 每轮新建，支持探索/定向两种模式 |
| **Analyzer** | 差分分析专家，推导安全属性 | 60 | **跨轮复用**，保留对话记忆 |
| **Patcher** | 漏洞修复专家，编辑源码 | 40 | 每轮新建多个，并行执行 |
| **Selector** | 补丁评估专家，选最优补丁 | - | 无工具，纯推理 |

**`agent.run(task=...)` 的内部流程**：

```
task 消息 → LLM
              ↓
         LLM 回复（可能包含工具调用）
              ↓
    ┌── 有工具调用？──┐
    │ 是              │ 否
    ↓                 ↓
执行工具           返回结果
    ↓
工具结果 → LLM     ← 循环（最多 max_tool_iterations 轮）
```

---

## 组件 4：ToolCallRequestEvent（工具调用事件）

**来源**：`autogen_agentchat.messages`

**作用**：`agent.run()` 返回的 `result.messages` 列表中，每当 Agent 请求调用工具时会产生一个 `ToolCallRequestEvent`，包含工具名称和参数。

**在本项目中的使用**（`pipeline.py:171-212`）：

```python
from autogen_agentchat.messages import ToolCallRequestEvent

def _extract_mutator_trace(messages):
    """从 Mutator 的对话轨迹中提取所有 bash 命令。"""
    commands = []
    for msg in messages:
        if isinstance(msg, ToolCallRequestEvent):
            for fc in msg.content:           # 一次可能调用多个工具
                if fc.name == "bash":
                    cmd = json.loads(fc.arguments)["command"]
                    commands.append(cmd)
    return commands
```

**用途**：
- 记录 Mutator 执行了哪些 bash 命令（变异操作轨迹）
- 追踪每个变体是由哪些命令生成的（mutation lineage）
- 保存到 `mutation_artifacts/` 供离线分析

---

## 编排模式：手动流水线 vs AutoGen GroupChat

本项目**没有使用** AutoGen 内置的 GroupChat/Team 编排机制，而是在 `pipeline.py` 中手动编排 Agent 执行顺序。

**原因与优势**：

```
AutoGen GroupChat 模式:
  Agent A → Agent B → Agent C → ...（由框架自动调度）
  ✗ 难以在阶段间插入硬性门控
  ✗ 难以实现"同轮重试 vs 跨轮反馈"的差异化策略
  ✗ 难以让 Agent 跨轮复用（保留记忆）

本项目的手动编排模式:
  for round in range(3):
      mutator.run()    → 门控检查 → 不满足则重试
      analyzer.run()   → reset_source() 清理探针
      patcher.run() ×2 → 空diff重试 / 编译失败重试 / 验证失败→下一轮
      verify()         → 完美补丁则提前退出
  selector.run()       → 多候选时选最优

  ✓ 每个阶段有精确的门控逻辑
  ✓ 闭环反馈（失败补丁 → 下一轮 Patcher 的上下文）
  ✓ Analyzer 跨轮复用（保留对话记忆，增量更新分析）
  ✓ Patcher 通过 asyncio.gather 并行执行在独立 Docker 容器中
```

---

## 运行示例

```bash
# 安装依赖
pip install autogen-agentchat autogen-ext[openai] docker datasets

# 配置环境变量
export SECBENCH_MODEL_NAME="gpt-5-mini"
export SECBENCH_BASE_URL="https://api.chatanywhere.tech/v1"
export SECBENCH_API_KEY="sk-..."

# 运行单个漏洞实例
python main.py --instance_id gpac.cve-2023-42298

# 运行组件演示
python autogen_demo.py
```

---

## 项目文件结构

```
secbench-solver/
├── main.py           入口：数据集加载、实例调度
├── pipeline.py       核心流水线：Stage 0→1→2 编排 + 门控逻辑（1687 行）
├── agents.py         4 个 Agent 工厂 + 系统提示词（488 行）
├── tools.py          FunctionTool 工厂：bash + str_replace_edit（150 行）
├── docker_tools.py   Docker 容器生命周期管理（297 行）
├── experience.py     双轨经验知识库：修复经验 + 变异经验（600 行）
├── repro_parser.py   SEC-bench repro 命令解析（185 行）
├── trajectory.py     Agent 对话轨迹序列化（165 行）
├── config.py         全局配置参数（33 行）
├── autogen_demo.py   AutoGen 组件使用演示脚本
└── results/          输出目录（补丁、轨迹、经验库）
```
