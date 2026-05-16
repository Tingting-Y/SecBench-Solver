import asyncio
import json
import logging
import os
import base64
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

# 导入现有代码库中的核心组件
from agents import create_model_client, create_analyzer, create_patcher
from docker_tools import stop_container, start_local_workspace_container, exec_cmd, write_file

# 复用 pipeline 的核心流水线方法
from pipeline import (
    _mutate, 
    _analyze, 
    _build_patcher_task, 
    _patch_single, 
    _get_repo_root,
    _test_variants_against_patch,
    _build_property_feedback
)
from experience import extract_vuln_type
from repro_parser import ReproCommand
from config import MAX_ADVERSARIAL_ROUNDS, MAX_MUTATION_RETRIES

# 创建一个日志格式器，包含时间、日志级别、所在模块和具体消息
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# 配置 FileHandler，将日志写入到 llm_interaction.log
file_handler = logging.FileHandler('llm_interaction.log', encoding='utf-8')
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)

# 配置 StreamHandler，让你在控制台也能实时看到
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.INFO)

# 设置根日志记录器
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)

# 这样，server.py 中原有的 logger 也会自动应用这些设置
logger = logging.getLogger(__name__)

app = FastAPI()
model_client = create_model_client(temperature=0.7)

class FixRequest(BaseModel):
    workspace_path: str
    file_path: str
    crash_log: str
    build_cmd: str = "make"

@app.websocket("/ws/fix")
async def websocket_fix_endpoint(websocket: WebSocket):
    await websocket.accept()
    container_id = None
    try:
        data = await websocket.receive_text()
        request_data = json.loads(data)
        workspace_path = request_data.get("workspace_path")
        crash_log = request_data.get("crash_log", "")
        
        await websocket.send_json({"type": "status", "message": "正在初始化安全沙箱..."})
        
        # 启动挂载了本地代码的 Docker 容器
        container_id = start_local_workspace_container(workspace_path, image="secbench-base:latest")
        
        await websocket.send_json({"type": "status", "message": "沙箱已启动，准备启动多智能体修复流水线..."})
        
        await run_interactive_pipeline(websocket, container_id, workspace_path, crash_log)

    except WebSocketDisconnect:
        logger.info("VS Code Client disconnected.")
    except Exception as e:
        logger.error(f"Error during fixing: {e}")
        await websocket.send_json({"type": "error", "message": str(e)})
    finally:
        if container_id:
            try:
                # 动态获取挂载目录(/src)的原始宿主机 UID 和 GID，
                # 并将整个目录下的所有文件权限还给宿主机，防止本地 Git 报 Permission Denied
                exec_cmd(container_id, "chown -R $(stat -c '%u:%g' /src) /src")
                
                # 清理可能因意外中断残留的 Git 锁
                exec_cmd(container_id, "rm -f /src/.git/index.lock")
            except Exception as e:
                logger.warning(f"清理文件权限时出错: {e}")
            stop_container(container_id)
            logger.info(f"Cleaned up container {container_id}")


async def run_interactive_pipeline(websocket: WebSocket, container_id: str, workspace_path: str, crash_log: str):
    """
    带有完整校验门和回归测试的对抗修复流水线 (Adversarial Loop)
    """
    instance = {
        "instance_id": "vscode_local",
        "bug_report": "User submitted crash log:\n" + crash_log,
        "sanitizer_report": crash_log,
        "repo": workspace_path,
    }

    await websocket.send_json({"type": "status", "message": "正在获取工作区信息..."})
    repo_root = _get_repo_root(container_id)
    
    # ---------------------------------------------------------
    # 预处理：配置沙箱环境 (Git追踪 & 工具链伪造)
    # ---------------------------------------------------------
    await websocket.send_json({"type": "status", "message": "正在确立 Git 追踪基准线..."})
    exec_cmd(container_id, "git config --global --add safe.directory '*'")
    exec_cmd(container_id, f"cd {repo_root} && git config --global user.email 'secbench@example.com'")
    exec_cmd(container_id, f"cd {repo_root} && git config --global user.name 'SecBench'")
    exec_cmd(container_id, f"cd {repo_root} && git init && git add . && git commit -m 'Initial baseline' || true")

    await websocket.send_json({"type": "status", "message": "正在注入构建系统适配器 (secb)..."})
    secb_script = f"""#!/bin/bash
if [ "$1" == "build" ]; then
    cd {repo_root} && make
elif [ "$1" == "repro" ]; then
    cd {repo_root} && ./MP4Box
else
    $@
fi
"""
    secb_base64 = base64.b64encode(secb_script.encode('utf-8')).decode('utf-8')
    exec_cmd(container_id, f"echo {secb_base64} | base64 -d > /usr/local/bin/secb")
    exec_cmd(container_id, "chmod +x /usr/local/bin/secb")

    # ---------------------------------------------------------
    # 初始化变量
    # ---------------------------------------------------------
    orig_vuln_type = extract_vuln_type(crash_log)
    orig_output = crash_log
    repro_cmd = ReproCommand(
        poc_path="/testcase/poc", 
        poc_type="text",            # 明确告诉大模型这是文本文件，不要去写 C 代码
        binary="./MP4Box",          
        args="{poc}", 
        cmd_template="./MP4Box {poc}" # 运行时将文件路径作为参数传入
    )
    orig_poc = "1"  # 初始的触发漏洞输入
# ================== 【新增代码开始：构建测试用例沙箱】 ==================
    await websocket.send_json({"type": "status", "message": "正在挂载测试用例环境..."})
    
    # 1. 创建 /testcase 目录
    exec_cmd(container_id, "mkdir -p /testcase")
    
    # 2. 将 PoC 内容写入容器内的 /testcase/poc 文件中
    write_file(container_id, "/testcase/poc", orig_poc)
    
    # 3. 赋予执行权限 (因为目前设定 repro_cmd 是 bash 脚本)
    exec_cmd(container_id, "chmod +x /testcase/poc")
    # ================== 【新增代码结束】 ==================
    all_crash_reports = []
    all_patches_feedback = []
    prev_property_report = ""
    candidates = []
    
    analyzer_agent = create_analyzer(model_client, container_id, single_crash=False)

    for round_num in range(MAX_ADVERSARIAL_ROUNDS):
        await websocket.send_json({"type": "status", "message": f"=== 第 {round_num + 1}/{MAX_ADVERSARIAL_ROUNDS} 轮对抗修复 ==="})
        
        prev_patch = all_patches_feedback[-1]["patch"] if all_patches_feedback else ""
        prev_feedback = all_patches_feedback[-1]["feedback"] if all_patches_feedback else ""

        # =========================================================
        # 阶段 1: Mutator (带重试校验门)
        # =========================================================
        await websocket.send_json({"type": "agent_switch", "agent": "Mutator"})
        await websocket.send_json({"type": "status", "message": "Mutator 正在生成变异测试用例并验证..."})
        
        mutation_feedback = ""
        round_crash_reports = []
        
        for mutation_attempt in range(1 + MAX_MUTATION_RETRIES):
            if mutation_attempt > 0:
                exec_cmd(container_id, "for f in /testcase/variant_*; do [ -e \"$f\" ] && rm -f \"$f\"; done")
                await websocket.send_json({"type": "status", "message": f"未产生有效的差异对比用例，正在进行第 {mutation_attempt+1} 次尝试..."})

            try:
                round_crash_reports, _ = await _mutate(
                    model_client=model_client, container_id=container_id,
                    repro_cmd=repro_cmd, orig_poc=orig_poc, orig_output=orig_output,
                    instance=instance, round_num=round_num,
                    prev_patch=prev_patch, prev_feedback=(prev_feedback + "\n" + mutation_feedback).strip(),
                    prev_crash_reports=all_crash_reports if round_num > 0 else None,
                    property_info=prev_property_report if round_num > 0 else "",
                    orig_vuln_type=orig_vuln_type
                )
                
                num_crashed = sum(1 for r in round_crash_reports if r["crashed"])
                num_not_crashed = sum(1 for r in round_crash_reports if not r["crashed"])

                # 校验门：必须既有崩溃的输入，也有不崩溃的输入，才能做差异分析
                if num_crashed > 0 and num_not_crashed > 0:
                    break 
                elif num_crashed == 0:
                    mutation_feedback = "IMPORTANT: None of your previous variants triggered the target vulnerability. Produce at least 1 variant that crashes with the SAME sanitizer error type."
                elif num_not_crashed == 0:
                    mutation_feedback = "IMPORTANT: ALL of your variants crashed. Produce at least 1 variant that does NOT crash for differential root cause analysis."
            except Exception as e:
                logger.warning(f"Mutator failed: {e}")
                break

        all_crash_reports.extend(round_crash_reports)
        await websocket.send_json({"type": "text", "agent": "Mutator", "content": f"变异生成完毕，本轮共收集到 {len(round_crash_reports)} 个具有对比价值的变异输入。"})

        # =========================================================
        # 阶段 2: Analyzer (差异化根因分析)
        # =========================================================
        await websocket.send_json({"type": "agent_switch", "agent": "Analyzer"})
        await websocket.send_json({"type": "status", "message": "Analyzer 正在根据崩溃/非崩溃报告推导安全属性..."})
        try:
            property_report = await _analyze(
                analyzer=analyzer_agent, container_id=container_id, repo_root=repo_root,
                orig_output=orig_output, all_crash_reports=all_crash_reports,
                new_crash_reports=round_crash_reports, instance=instance, round_num=round_num,
                repro_cmd_str="", prev_patch=prev_patch, prev_feedback=prev_feedback
            )
            prev_property_report = property_report
            await websocket.send_json({"type": "text", "agent": "Analyzer", "content": property_report})
        except Exception as e:
            logger.error(f"Analyzer failed: {e}")
            property_report = prev_property_report
            await websocket.send_json({"type": "text", "agent": "Analyzer", "content": f"分析受阻，使用历史报告。错误: {str(e)}"})

        # =========================================================
        # 阶段 3: Patcher (带变异回归测试)
        # =========================================================
        await websocket.send_json({"type": "agent_switch", "agent": "Patcher"})
        await websocket.send_json({"type": "status", "message": "Patcher 正在编写初步补丁并进行本地编译验证..."})
        
        task_prompt = _build_patcher_task(
            repo_root=repo_root, orig_output=orig_output, all_crash_reports=all_crash_reports,
            new_crash_reports=round_crash_reports, instance=instance, round_num=round_num,
            property_report=property_report, all_patches_feedback=all_patches_feedback if all_patches_feedback else None
        )

        patcher_agent = create_patcher(model_client, container_id, name="Patcher")
        patch_result = await _patch_single(
            patcher=patcher_agent, container_id=container_id, repo_root=repo_root,
            task=task_prompt, expected_exit_code=0, orig_vuln_type=orig_vuln_type,
            model_client=model_client
        )

        if patch_result.get("diff"):
            if patch_result["verified"]:
                await websocket.send_json({"type": "status", "message": "初步编译验证通过，正在运行所有历史变异用例进行回归测试..."})
                
                # 校验门：使用之前累积的所有变异用例测试当前的补丁
                vr = _test_variants_against_patch(
                    container_id, repro_cmd, all_crash_reports, orig_vuln_type=orig_vuln_type
                )
                
                candidates.append({
                    "patch": patch_result["diff"],
                    "round": round_num + 1,
                    "property_report": property_report,
                    "variant_test_result": vr
                })
                
                still_crashed = vr.get("still_crashed", 999)
                if still_crashed == 0:
                    await websocket.send_json({"type": "status", "message": "✅ 补丁完美通过了所有边界变异的回归测试！"})
                    break  # 找到完美的鲁棒性补丁，退出大循环
                else:
                    await websocket.send_json({"type": "status", "message": f"❌ 补丁有效但未覆盖边界：仍有 {still_crashed} 个变异用例触发崩溃，准备进入下一轮对抗..."})
                    fb = _build_property_feedback(property_report, vr, all_crash_reports)
                    all_patches_feedback.append({
                        "patch": patch_result["diff"],
                        "feedback": fb,
                        "round": round_num + 1
                    })
                    # 🟢 修改为普通的 text 消息，避免触发前端的断开逻辑
                    await websocket.send_json({
                        "type": "text", 
                        "agent": "System",
                        "content": f"⚠️ 尝试的补丁未通过变异用例的回归测试，准备进入下轮对抗。\n\n**当前未通过的反馈：**\n```text\n{fb}\n```"
                    })
            else:
                await websocket.send_json({"type": "status", "message": "❌ 补丁未能通过初步编译或导致程序异常退出了..."})
                all_patches_feedback.append({
                    "patch": patch_result["diff"],
                    "feedback": patch_result.get("feedback", "Verification failed"),
                    "round": round_num + 1
                })
        else:
            await websocket.send_json({"type": "status", "message": "Patcher 本轮未能生成有效的代码修改。"})
            all_patches_feedback.append({
                "patch": "",
                "feedback": "No source code changes produced. Use the str_replace_edit tool.",
                "round": round_num + 1
            })

    # =========================================================
    # 阶段 4: Selector 判定并返回最终结果
    # =========================================================
    await websocket.send_json({"type": "status", "message": "修复流水线执行完毕，正在评估并生成最终结果..."})
    
    if candidates:
        # 检查候选池中是否有 0 崩溃的“完美补丁”
        perfect_candidates = [c for c in candidates if c.get("variant_test_result", {}).get("still_crashed", 999) == 0]
        
        if perfect_candidates:
            # 如果有完美补丁，取最新的一个
            best_patch = perfect_candidates[-1]
            await websocket.send_json({
                "type": "result", 
                "status": "success", 
                "message": "✅ 成功找到覆盖所有安全边界的完美补丁！",
                "diff": best_patch["patch"]
            })
        else:
            # 如果没有完美补丁，但有候选者，则挑选“仍然崩溃数量最少”的那个（模拟 Selector 行为）
            best_patch = min(candidates, key=lambda c: c.get("variant_test_result", {}).get("still_crashed", 999))
            still_crashed = best_patch.get("variant_test_result", {}).get("still_crashed", "?")
            
            await websocket.send_json({
                "type": "result", 
                "status": "partial_success", 
                "message": f"⚠️ 经过多轮对抗未能找到100%覆盖边界的补丁。已选择鲁棒性最高的版本（仍有 {still_crashed} 个变异用例未通过），请人工复核。",
                "diff": best_patch["patch"]
            })
    else:
        # 连最初始的 PoC 都没修好
        last_patch = all_patches_feedback[-1]["patch"] if all_patches_feedback else ""
        if last_patch:
            await websocket.send_json({
                "type": "result", "status": "failed",
                "message": "❌ 修复失败：补丁未能通过最基本的崩溃验证。",
                "diff": last_patch
            })
        else:
            await websocket.send_json({
                "type": "result", "status": "failed",
                "message": "❌ 修复失败，经过多轮尝试均未能生成有效的补丁代码。"
            })
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)