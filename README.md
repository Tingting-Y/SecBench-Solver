# SecBench-Solver

自动修复 C/C++ 内存安全漏洞的多智能体对抗流水线。

输入一个 [SEC-bench](https://huggingface.co/datasets/SEC-bench/SEC-bench) 漏洞实例（含 sanitizer 崩溃报告 + Docker 环境），输出经过验证的补丁 diff。

## 核心思路

```
 崩溃报告 ──Mutator──> PoC 变体群
                        │
                  崩溃 vs 不崩溃 的差分
                        │
                    Analyzer ──> 安全属性 (形式化的根因条件)
                        │
                    Patcher ──> 针对性修复 (不是猜，是有依据地改)
                        │
                  原始 PoC + 全部变体 验证
                        │
                        ──反馈──> 下一轮对抗
```

关键区别：Patcher 不是在盲猜修复，而是基于 Analyzer 推导出的精确安全属性（如 "index < array->length before access at file.c:123"）进行定向修复。

**崩溃判断一致性**：变体是否"崩溃"的判断标准与原始 PoC 严格一致——必须触发**同类型**的 sanitizer 错误（如原始为 `heap-buffer-overflow`，则只有同样触发 `heap-buffer-overflow` 的变体才算崩溃）。触发不同类型错误的变体被视为"不崩溃"，避免无关错误污染差分分析。

**双向变异**：Mutator 必须同时产出崩溃和不崩溃的变体。不崩溃的变体是刻意设计的"差一点就触发"的输入（如 index=size-1 vs index=size），为 Analyzer 提供精确的边界条件信号。

## 架构总览

```
main.py                          入口：加载数据集，逐实例调度
  │
  └─> pipeline.solve_instance()  核心流水线
        │
        ├── Stage 0: Setup       启动容器 → build → 验证原始 PoC 崩溃
        │
        ├── Stage 1: Adversarial Loop (最多 3 轮)
        │     │
        │     ├── Mutator        生成 PoC 变体，验证至少 1 个崩溃 (带重试门控)
        │     ├── Analyzer       差分属性发现 + 动态探针验证 (跨轮记忆)
        │     ├── Patcher        并行修复 + 经验检索 (空 diff/编译失败同轮重试；验证失败跨轮反馈)
        │     └── Verify         原始 PoC + 累积变体 鲁棒性测试
        │
        └── Stage 2: Selection   多候选时 Selector 选最优补丁

支撑模块:
  agents.py        4 个 Agent 工厂 + 系统提示词
  tools.py         bash / str_replace_edit 工具 (绑定到容器)
  docker_tools.py  Docker 容器生命周期管理
  experience.py    经验知识库: 漏洞类型提取 + 三层优先级检索 + BM25
  repro_parser.py  SEC-bench repro 命令解析
  trajectory.py    Agent 对话轨迹记录
  config.py        全局配置参数
```

## 四个 Agent 的分工

| Agent | 工具 | 职责 | 迭代上限 |
|-------|------|------|----------|
| Mutator | `bash` | 生成 PoC 变体（崩溃+不崩溃），用于差分分析 | 30 |
| Analyzer | `bash` | 读源码 + 插动态探针 + build + run，推导安全属性 | 60 |
| Patcher | `bash`, `str_replace_edit` | 基于属性报告编辑源码修复漏洞 | 40 |
| Selector | (无) | 从多个候选补丁中选最鲁棒的 | - |

补丁收集原则：**LLM 只负责通过 `str_replace_edit` 编辑文件，diff 永远由 `git diff` 从容器文件系统收集**，绝不让 LLM 生成 diff 文本。

## 闭环验证门控 (Closed-Loop Gates)

流水线在每个阶段边界设置了硬性门控，防止无效数据向下传播：

```
Mutator ──生成变体──> 差分验证门控 (需要崩溃 + 不崩溃两类变体)
  │                    │
  │  崩溃判断:          │  变体触发的 sanitizer 错误类型必须与原始 PoC 一致
  │                    │  (如原始为 heap-buffer-overflow，变体也必须是同类型)
  │                    │
  │  0 个崩溃?         ├── 反馈 "必须触发同类型崩溃" → 重试
  │  全部崩溃?         ├── 反馈 "需要不崩溃的变体做差分" → 重试
  │  两类都有?         └── 通过 ✓ (最多重试 2 次)
  │
Analyzer ──插探针──> 源码重置验证
  │                    │
  │  reset_source()    ├── git status --porcelain 检查
  │  后仍有残留?       ├── 强制二次 reset + 警告日志
  │                    └── 干净 ✓
  │
Patcher ──编辑源码──> 三重门控
  │
  ├── Gate 1: git diff 非空?
  │     空 → 新建 Patcher + 反馈 "必须用 str_replace_edit" → 重试
  │
  ├── Gate 2: secb build 通过?
        失败 → 新建 Patcher + 编译错误反馈 → 重试
        (每个 Gate 最多重试 2 次)
  │
  └── Gate 3: secb repro 验证通过?
        条件: 不再触发同类型 sanitizer 且 exit ∈ {0, expected_exit_code}
        失败 → 不在本轮重试，作为失败反馈进入下一大轮
```

## 双轨经验知识库 (Dual Experience Knowledge Base)

成功修复后自动积累两类经验，后续实例可以检索相似历史作为 few-shot 参考：

```
                    +------------------------+
                    |  experience_kb.jsonl   |  修复经验 → 注入 Patcher prompt
                    |  (patch experiences)    |  "这类漏洞通常怎么修"
                    +------------------------+
                    | mutation_experience_   |  变异经验 → 注入 Mutator prompt
                    |  kb.jsonl              |  "这类漏洞用什么变异策略有效"
                    +------------------------+
```

**漏洞类型提取**：从 sanitizer 输出自动识别 12 种漏洞类型：

```
heap-buffer-overflow | stack-buffer-overflow | global-buffer-overflow
use-after-free       | double-free           | null-pointer-dereference
SEGV                 | use-of-uninitialized-value | memory-leak
stack-overflow       | integer-overflow       | undefined-behavior
```

**三层优先级检索**（两个 KB 共享相同检索策略）：

```
优先级 1: 同仓库 + 同漏洞类型    (如 gpac 的另一个 heap-buffer-overflow)
优先级 2: 不同仓库 + 同漏洞类型  (如 mruby 的 heap-buffer-overflow)
优先级 3: BM25 相似度兜底        (基于 bug_description + sanitizer_report)
```

默认配置下，两个经验库都会在**每一大轮**重新检索；第 2 轮及以后，Patcher prompt 还会额外注入
“上一轮失败补丁 → 检索到的成功补丁”的对照示例，强化修复方向区分。

**漏洞类型特定的变异策略**：`experience.py` 内置了基于领域知识的变异策略映射表（借鉴 SecVerifier 的漏洞利用生成方法），为每种漏洞类型提供专家级变异指导。例如：

- `heap-buffer-overflow` → 增大输入超过缓冲区长度、变异长度字段、使用边界值
- `use-after-free` → 触发对象销毁后再引用、交错分配/释放序列
- `null-pointer-dereference` → 删除可选字段、提供空容器、触发跳过初始化的错误路径

这些策略提示 + 历史变异经验一起注入 Mutator 的 prompt，让变异不再是随机的。

**经验闭环**：

```
实例 1 成功修复
  ├── 保存: 修复经验 {patch, property_report}
  └── 保存: 变异经验 {哪些变体崩溃了, 哪些没有}
              │
实例 2 开始处理
  ├── Mutator 检索: 静态策略提示 + 实例 1 的变异经验
  └── Patcher 检索: 实例 1 的修复经验
              │
实例 N ... (知识库越来越大，后续实例受益越多)
```

## 完整执行流程

```
对每个 SEC-bench 实例:

Stage 0: 环境准备
  ├── 启动 Docker 容器 (hwiwonlee/secb.eval.x86_64.<id>:patch)
  ├── secb build 编译项目
  ├── secb repro 验证原始 PoC 触发 sanitizer 崩溃
  └── 解析 repro 命令模板，定位源码根目录

Stage 1: 对抗循环 (最多 3 轮)
  │
  │  ┌─ Step 1: Mutate ──────────────────────────────────────┐
  │  │  Mutator agent 生成 N 个 PoC 变体 (崩溃 + 不崩溃)      │
  │  │  每个变体运行后判断: 是否触发与原始 PoC 同类型的崩溃     │
  │  │  [门控] 需要 ≥1 崩溃 AND ≥1 不崩溃 (差分分析必需)       │
  │  │         不满足 → 清理 + 针对性反馈 → 重试 (最多 2 次)   │
  │  │  变体持久化为 /testcase/r<轮次>_variant_*               │
  │  └────────────────────────────────────────────────────────┘
  │  ┌─ Step 2: Analyze ─────────────────────────────────────┐
  │  │  Analyzer agent (跨轮复用，保留对话记忆)                 │
  │  │  对比崩溃/不崩溃变体 → 推导安全属性                      │
  │  │  每条变体报告都附带 Mutation lineage (how/commands)     │
  │  │  可插入动态探针 (fprintf) → build → run → 观察运行时值   │
  │  │  [门控] 分析完毕后 reset_source + git status 验证干净    │
  │  │  输出: Property Analysis Report                        │
  │  └────────────────────────────────────────────────────────┘
  │  ┌─ Step 3: Patch ───────────────────────────────────────┐
  │  │  检索经验知识库 → 注入相似修复案例到 prompt              │
  │  │  启动 N 个并行容器，每个运行一个 Patcher agent           │
  │  │  Patcher 通过 str_replace_edit 编辑源码                 │
  │  │  git diff 收集补丁 (绝不让 LLM 生成 diff 文本)          │
  │  │  [门控] 空 diff/编译失败 → 同轮重试 (最多 2 次)          │
  │  │  [验证] 原始 PoC 验证失败 → 记录反馈，进入下一大轮        │
  │  │  去重后收集候选 diff 列表                                │
  │  └────────────────────────────────────────────────────────┘
  │  ┌─ Step 4: Verify ──────────────────────────────────────┐
  │  │  Step 3 已完成 in-place 原始 PoC 验证                    │
  │  │  对 verified diff: 在主容器 apply → build → 全部变体测试  │
  │  │  完美补丁 (0 变体仍崩溃) → 提前退出                     │
  │  │  失败补丁 → 反馈进入下一轮                               │
  │  └────────────────────────────────────────────────────────┘
  │
  │  轮间反馈传播:
  │    - 失败补丁 + 失败原因（全部保留，不做筛选）→ 下一轮 Patcher 的历史上下文
  │    - 未解决的安全属性 → 下一轮 Mutator 的定向变异目标
  │    - Analyzer 保留完整对话记忆，增量更新属性报告

Stage 2: 选择
  ├── 0 个候选 → 返回 "failed"
  ├── 1 个候选 → 直接使用
  └── N 个候选 → Selector agent 评估选最优
       评估维度: 变体鲁棒性 > 根因正确性 > 最小化 > 安全性

成功后: 保存经验到知识库 → 惠及后续实例
```

## 跨轮数据积累

```
                Round 0          Round 1          Round 2
变体:           3 个             +3 = 6 个        +3 = 9 个
验证严格度:     测 3 个变体      测 6 个变体      测 9 个变体
失败补丁历史:   0 条             +N 条            +N 条
Analyzer 记忆:  初始分析         增量更新         增量更新
```

越往后轮次，验证越严格，Patcher 获得的上下文越丰富。

## 配置参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `MODEL_NAME` | `gpt-5-mini` | LLM 模型 (环境变量 `SECBENCH_MODEL_NAME`) |
| `BASE_URL` | `https://api.chatanywhere.tech/v1` | API 端点 (环境变量 `SECBENCH_BASE_URL`) |
| `MAX_ADVERSARIAL_ROUNDS` | 3 | 对抗循环最大轮数 |
| `MAX_MUTATION_VARIANTS` | 3 | 每轮生成的 PoC 变体数 |
| `PATCHES_PER_ROUND` | 2 | 每轮并行 Patcher 数量 |
| `PATCHER_TEMPERATURE` | 1 | Patcher 采样温度 |
| `MAX_MUTATION_RETRIES` | 2 | 变体零崩溃时的重试次数 |
| `MAX_PATCHER_RETRIES` | 2 | 空 diff / 编译失败时的重试次数 |
| `PATCH_EXPERIENCE_MAX_EXAMPLES` | 2 | 每轮注入给 Patcher 的修复经验条数 |
| `MUTATION_EXPERIENCE_MAX_EXAMPLES` | 1 | 每轮注入给 Mutator 的变异经验条数 |
| `RETRIEVE_EXPERIENCE_EVERY_ROUND` | `True` | 是否每一大轮都重新检索经验（否则仅第 1 轮） |
| `ENABLE_PATCH_REFINEMENT_DEMO` | `True` | 在第 2+ 轮注入“失败补丁 → 成功示例”对照块 |
| `ANALYZER_MAX_TOOL_ITERS` | 60 | Analyzer 最大工具调用轮数 |

## 使用方法

### 前置条件

- Python 3.11+
- Docker daemon 运行中
- SEC-bench Docker 镜像已拉取
- 依赖: `pip install autogen-agentchat autogen-ext docker datasets`

### 运行

```bash
# 全部实例
python main.py

# 单个实例
python main.py --instance_id gpac.cve-2023-42298

# 范围运行
python main.py --start 0 --end 10
```

### 输出

```
results/
├── <instance_id>.json              # 结果 (status, patch, 鲁棒性评分, 属性报告)
├── <instance_id>.diff              # 补丁文件 (成功时)
├── <instance_id>.traj.json         # Agent 对话轨迹 (调试用)
├── mutation_artifacts/<instance_id>/
│   └── round_<r>/attempt_<k>/      # 变异工件（每次尝试都会落盘）
│       ├── metadata.json           # 变异谱系: mutation_how / mutation_commands / sha256 / crash标记
│       ├── variants/               # 变体文件快照（从容器复制到主机）
│       └── repro_outputs/*.log     # 每个变体完整复现输出
├── experience_kb.jsonl             # 修复经验知识库 (自动积累)
├── mutation_experience_kb.jsonl    # 变异经验知识库 (自动积累)
└── solver.log                      # 运行日志
```

### 常见日志解释

- `retrying within round (attempt x/y)`：同一大轮内重试，触发条件仅为 `空 diff` 或 `build 失败`。
- `patch did not pass verification; defer improvement to next adversarial round`：补丁已编译但未通过验证，不在本轮重试，转入下一大轮。

### 断点续跑

已有结果的实例自动跳过。要重跑某个实例：

```bash
rm results/gpac.cve-2023-42298.json
python main.py --instance_id gpac.cve-2023-42298
```

## 文件结构

```
secbench-solver/
├── main.py           入口: CLI 参数解析, 数据集加载, 实例调度, 结果保存
├── pipeline.py       核心流水线: Setup → Mutate → Analyze → Patch → Verify → Select
├── agents.py         Agent 工厂 + 系统提示词 (Mutator/Analyzer/Patcher/Selector)
├── experience.py     经验知识库: 漏洞类型提取, 三层优先级 BM25 检索, prompt 格式化
├── tools.py          工具工厂: bash + str_replace_edit (闭包绑定到容器)
├── docker_tools.py   Docker 操作: 容器启停, 命令执行, 文件读写, build/repro/patch
├── repro_parser.py   SEC-bench repro 命令模板解析
├── trajectory.py     Agent 对话轨迹序列化
├── config.py         全局配置参数
└── results/          输出目录
```
