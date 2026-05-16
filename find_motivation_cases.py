import os
import json
import glob
import shutil

# ================= 配置区 =================
# 完整 Pipeline 成功的存放目录
FULL_PIPELINE_DIR = "results_gpt"

# 纯静态基线失败的存放目录
BASELINE_DIR = "results_E1"

# 🌟 新增：集中存放黄金案例对比文件的输出目录
OUTPUT_DIR = "golden_motivation_cases"

SUCCESS_STATUSES = ["success"] 
FAILURE_STATUSES = ["failed", "error", "build_failed"]

def check_status(filepath):
    """读取 JSON 文件并返回其 status 状态"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get("status", "unknown").lower()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return "error"

def find_golden_cases():
    print(f"🔍 开始寻找黄金案例: 完整流水线 ({FULL_PIPELINE_DIR}) 成功 vs 基线 ({BASELINE_DIR}) 失败...\n")
    
    # 获取完整流水线中所有的 instance_id
    full_pipeline_files = glob.glob(os.path.join(FULL_PIPELINE_DIR, "*.json"))
    # 过滤掉 traj 轨迹文件，只看主结果文件
    full_pipeline_files = [f for f in full_pipeline_files if not f.endswith(".traj.json")]
    
    golden_cases = []
    
    # 🌟 新增：创建目标文件夹
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    for full_path in full_pipeline_files:
        filename = os.path.basename(full_path)
        instance_id = filename.replace(".json", "")
        
        # 构建对应的 baseline 文件路径
        baseline_path = os.path.join(BASELINE_DIR, filename)
        
        # 如果 baseline 里没有跑这个例子，跳过
        if not os.path.exists(baseline_path):
            continue
            
        # 获取两边的状态
        full_status = check_status(full_path)
        baseline_status = check_status(baseline_path)
        
        # 判断是否满足交集条件：完整版成功，且 Baseline 失败
        is_full_success = any(s in full_status for s in SUCCESS_STATUSES)
        is_baseline_failure = any(s in baseline_status for s in FAILURE_STATUSES)
        
        if is_full_success and is_baseline_failure:
            golden_cases.append({
                "instance_id": instance_id,
                "full_status": full_status,
                "baseline_status": baseline_status
            })
            
            # 🌟 新增：定位源轨迹文件
            baseline_traj_src = os.path.join(BASELINE_DIR, f"{instance_id}.traj.json")
            full_traj_src = os.path.join(FULL_PIPELINE_DIR, f"{instance_id}.traj.json")
            
            # 🌟 新增：定义目标文件路径（并重命名）
            baseline_traj_dest = os.path.join(OUTPUT_DIR, f"{instance_id}_E1.traj.json")
            full_traj_dest = os.path.join(OUTPUT_DIR, f"{instance_id}_gpt.traj.json")
            
            # 🌟 新增：执行拷贝操作
            if os.path.exists(baseline_traj_src):
                shutil.copy2(baseline_traj_src, baseline_traj_dest)
            if os.path.exists(full_traj_src):
                shutil.copy2(full_traj_src, full_traj_dest)
            
    # ================= 输出结果 =================
    if not golden_cases:
        print("😭 没有找到符合条件的案例。你可以检查一下 STATUS 的判定条件是否正确。")
        return
        
    print(f"🎉 找到了 {len(golden_cases)} 个绝佳的候选案例！相关文件已提取至 '{OUTPUT_DIR}' 文件夹。\n")
    for case in golden_cases:
        print(f"🌟 Instance ID: {case['instance_id']}")
        print(f"   ├─ 完整流水线状态: {case['full_status']}")
        print(f"   └─ Baseline状态  : {case['baseline_status']}")
        print(f"   👉 下一步: 去看 {OUTPUT_DIR}/{case['instance_id']}_E1.traj.json 和 _gpt.traj.json")
        print("-" * 50)

if __name__ == "__main__":
    find_golden_cases()