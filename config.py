"""Global configuration for SEC-bench solver."""

import os

MODEL_NAME = os.environ.get("SECBENCH_MODEL_NAME", "gpt-5-mini")
BASE_URL = os.environ.get("SECBENCH_BASE_URL", "https://api.chatanywhere.tech/v1")
API_KEY = os.environ.get("SECBENCH_API_KEY", "sk-gwmeIT7LPFQpZGwMACKdnAJDg0T6bwtXBm4I9ah6zOM28bbe")
# MODEL_NAME = os.environ.get("SECBENCH_MODEL_NAME", "Pro/deepseek-ai/DeepSeek-V3.2")
# BASE_URL = os.environ.get("SECBENCH_BASE_URL", "https://api.siliconflow.cn/v1")
# API_KEY = os.environ.get("SECBENCH_API_KEY", "sk-ajlpkwnmeskkuxiypbwqapsvixtxlounifsjhancsmgudhsg")
# MODEL_NAME = os.environ.get("SECBENCH_MODEL_NAME", "deepseek-chat")
# BASE_URL = os.environ.get("SECBENCH_BASE_URL", "https://api.deepseek.com/v1")
# API_KEY = os.environ.get("SECBENCH_API_KEY", "sk-25fa8152504e4326b2323a1a563306e1")
# Adversarial loop parameters
MAX_ADVERSARIAL_ROUNDS = 3      # Max rounds of mutate-patch iteration
MAX_MUTATION_VARIANTS = 3        # Number of PoC variants to generate per round
PATCHES_PER_ROUND = 2           # Number of parallel Patcher agents per round
PATCHER_TEMPERATURE = 1      # Temperature for Patcher sampling (diversity)
DOCKER_EXEC_TIMEOUT = 300       # Docker command timeout (seconds)
BUILD_TIMEOUT = 300             # Build timeout (seconds)
RESULTS_DIR = os.environ.get("RESULTS_DIR", "./results_gpt")
INSTANCE_TIMEOUT = 3600         # Per-instance timeout in seconds (60 min)

# Closed-loop retry limits
MAX_MUTATION_RETRIES = 0      # Retry mutation if 0 variants crash
MAX_PATCHER_RETRIES = 1        # Retry patcher if empty diff or build failure

# Agent tool-calling iterations (how many tool rounds each agent may take)
MUTATOR_MAX_TOOL_ITERS = 40
PATCHER_MAX_TOOL_ITERS = 40
ANALYZER_MAX_TOOL_ITERS = 60   # Analyzer reads source + inserts probes + builds + runs

# Maximum characters returned by bash tool before truncation
MAX_OUTPUT_LENGTH = 66000

# Docker image prefix for SEC-bench
DOCKER_IMAGE_PREFIX = "hwiwonlee/secb.eval.x86_64"
DOCKER_IMAGE_TAG = "patch"

# ============================================================================
# 消融实验配置
# ============================================================================
#
#                    差分分析                 经验知识库
#   实验      PoC变异  崩溃分析      补丁修复经验  PoC变异实践经验                       RESULTS_DIR
#   ─────────────────────────────────────────────────────────────────────────────────────────────────
#   Baseline    ✓        ✓          ✓            ✓          完整系统                    ./results
#   E1          ✗        ✗          ✗            ✗          纯Patcher（最低基线）        ./results_E1
#   E2          ✗        ✓          ✓            ✓          去掉变异,Analyzer只分析原始   ./results_E2
#   E3          ✓        ✗          ✓            ✓          去掉分析,Patcher看崩溃报告   ./results_E3
#   E4          ✓        ✓          ✗            ✗          去掉全部经验                 ./results_E4
#   E5          ✓        ✓          ✗            ✓          只去掉Patcher经验            ./results_E5
#   E6          ✓        ✓          ✓            ✗          只去掉Mutation经验           ./results_E6
#
ABLATION_SKIP_MUTATOR = os.environ.get("ABLATION_SKIP_MUTATOR", "0") == "1"
ABLATION_SKIP_ANALYZER = os.environ.get("ABLATION_SKIP_ANALYZER", "0") == "1"
ABLATION_SKIP_PATCHER_EXP = os.environ.get("ABLATION_SKIP_PATCHER_EXP", "0") == "1"
ABLATION_SKIP_MUTATION_EXP = os.environ.get("ABLATION_SKIP_MUTATION_EXP", "0") == "1"