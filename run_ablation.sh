#!/bin/bash
# 消融实验并行运行脚本
# 用法: bash run_ablation.sh
#
# 每个实验在后台运行，日志输出到各自的 RESULTS_DIR/solver.log
# 通过环境变量控制消融 flag，互不冲突

set -e
cd "$(dirname "$0")"

echo ""
echo "=========================================="
echo " 启动消融实验 E2 ~ E6"
echo "=========================================="

# 创建结果目录
mkdir -p ./results_E2 ./results_E3 ./results_E4 ./results_E5 ./results_E6

# E1 已单独运行（纯 Patcher 基线，resultsA12）

# E2: 去掉 Mutator, Analyzer 只分析原始崩溃
echo "[E2] 去掉变异, Analyzer 只分析原始崩溃..."
RESULTS_DIR=./results_E2 \
ABLATION_SKIP_MUTATOR=1 \
ABLATION_SKIP_ANALYZER=0 \
ABLATION_SKIP_PATCHER_EXP=0 \
ABLATION_SKIP_MUTATION_EXP=0 \
nohup python main.py > ./results_E2/run.log 2>&1 &
echo "  PID=$!"

# E3: 去掉 Analyzer, Patcher 看原始报告
echo "[E3] 去掉分析, Patcher 看原始报告..."
RESULTS_DIR=./results_E3 \
ABLATION_SKIP_MUTATOR=0 \
ABLATION_SKIP_ANALYZER=1 \
ABLATION_SKIP_PATCHER_EXP=0 \
ABLATION_SKIP_MUTATION_EXP=0 \
nohup python main.py > ./results_E3/run.log 2>&1 &
echo "  PID=$!"

# E4: 去掉全部经验
echo "[E4] 去掉全部经验..."
RESULTS_DIR=./results_E4 \
ABLATION_SKIP_MUTATOR=0 \
ABLATION_SKIP_ANALYZER=0 \
ABLATION_SKIP_PATCHER_EXP=1 \
ABLATION_SKIP_MUTATION_EXP=1 \
nohup python main.py > ./results_E4/run.log 2>&1 &
echo "  PID=$!"

# E5: 只去掉 Patcher 经验
echo "[E5] 只去掉 Patcher 经验..."
RESULTS_DIR=./results_E5 \
ABLATION_SKIP_MUTATOR=0 \
ABLATION_SKIP_ANALYZER=0 \
ABLATION_SKIP_PATCHER_EXP=1 \
ABLATION_SKIP_MUTATION_EXP=0 \
nohup python main.py > ./results_E5/run.log 2>&1 &
echo "  PID=$!"

# E6: 只去掉 Mutation 经验
echo "[E6] 只去掉 Mutation 经验..."
RESULTS_DIR=./results_E6 \
ABLATION_SKIP_MUTATOR=0 \
ABLATION_SKIP_ANALYZER=0 \
ABLATION_SKIP_PATCHER_EXP=0 \
ABLATION_SKIP_MUTATION_EXP=1 \
nohup python main.py > ./results_E6/run.log 2>&1 &
echo "  PID=$!"

echo ""
echo "=========================================="
echo " 全部已启动，查看进度:"
echo "  tail -f ./results_E2/run.log"
echo "  tail -f ./results_E3/run.log"
echo "  tail -f ./results_E4/run.log"
echo "  tail -f ./results_E5/run.log"
echo "  tail -f ./results_E6/run.log"
echo "=========================================="
