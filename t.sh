
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