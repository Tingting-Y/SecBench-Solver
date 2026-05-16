"""Docker container interaction tools for SEC-bench solver."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile

import docker

from config import BUILD_TIMEOUT, DOCKER_EXEC_TIMEOUT

logger = logging.getLogger(__name__)

def start_local_workspace_container(workspace_path: str, image: str = "ubuntu:22.04") -> str:
    """
    启动一个用于 VS Code 插件交互的容器，将本地工作区挂载到 /src。
    
    Args:
        workspace_path: VS Code 传入的本地项目绝对路径
        image: 基础开发镜像（建议用户提前构建好包含 gcc/clang/make 的基础镜像）
    """
    cmd = [
        "docker", "run", "-d", "--rm",
        "-v", f"{workspace_path}:/src",  # 关键：挂载本地目录
        "-w", "/src",                    # 设置工作目录
        image, 
        "tail", "-f", "/dev/null"        # 保持容器运行
    ]
    
    logger.info("Starting local workspace container with cmd: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    container_id = result.stdout.strip()
    logger.info("Local container started: %s", container_id)
    
    # 初始化 git 仓库（如果本地没有），方便后续使用 git diff 提取补丁
    subprocess.run(["docker", "exec", container_id, "git", "init"], capture_output=True)
    subprocess.run(["docker", "exec", container_id, "git", "add", "."], capture_output=True)
    
    return container_id

_client: docker.DockerClient | None = None

# ---------------------------------------------------------------------------
# Output cleaning — strip ANSI escapes and control chars from container output
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
_CR_RE = re.compile(r'\r')
_BRACKETED_PASTE_RE = re.compile(r'\x1B\[\?2004[lh]')
_OSC_RE = re.compile(r'\x1B\][0-9;]*[a-zA-Z0-9:\s@\-_./]*\x07')


def _clean_output(text: str) -> str:
    """Remove ANSI escapes and control characters from container output."""
    text = _ANSI_RE.sub('', text)
    text = _CR_RE.sub('', text)
    text = _BRACKETED_PASTE_RE.sub('', text)
    text = _OSC_RE.sub('', text)
    return text


def _get_client() -> docker.DockerClient:
    """Lazy-initialize and return the Docker client."""
    global _client
    if _client is None:
        _client = docker.from_env()
    return _client


def start_container(image: str) -> str:
    """Start a detached container running 'sleep infinity'.

    Returns the container ID.
    """
    client = _get_client()
    container = client.containers.run(
        image,
        command="sleep infinity",
        detach=True,
        # Host networking lets containers reach localhost-only proxy services
        # on the host (e.g. 127.0.0.1:15510 for GitHub access).
        network_mode="host",
        # Give the container access to build tools
        mem_limit="4g",
        # Security: don't give extra capabilities unless needed
    )
    logger.info("Started container %s from image %s", container.short_id, image)
    return container.id


def exec_cmd(
    container_id: str,
    cmd: str,
    timeout: int = DOCKER_EXEC_TIMEOUT,
) -> tuple[int, str, str]:
    """Execute a command inside a container.

    Returns (exit_code, stdout, stderr).
    """
    client = _get_client()
    container = client.containers.get(container_id)

    # Use exec_run with demux to separate stdout/stderr
    exit_code, output = container.exec_run(
        ["bash", "-c", cmd],
        demux=True,
        environment={"TIMEOUT": str(timeout)},
    )

    stdout = _clean_output(output[0].decode("utf-8", errors="replace")) if output[0] else ""
    stderr = _clean_output(output[1].decode("utf-8", errors="replace")) if output[1] else ""

    return exit_code, stdout, stderr


def read_file(container_id: str, path: str) -> str:
    """Read a file from inside the container using cat."""
    exit_code, stdout, stderr = exec_cmd(container_id, f"cat '{path}'")
    if exit_code != 0:
        raise FileNotFoundError(
            f"Failed to read {path} in container: {stderr}"
        )
    return stdout


def write_file(container_id: str, path: str, content: str | bytes) -> None:
    """Write content to a file inside the container via ``docker cp``.

    Following MemRepair's approach: write to a host temp file, then use the
    ``docker cp`` CLI command to copy it into the container.  This avoids
    the ``put_archive`` SDK API which does not respect the container's
    WORKDIR and has caused silent write-to-wrong-path bugs.

    Relative paths are resolved against the container's working directory.
    """
    import posixpath

    # Resolve relative paths
    if not posixpath.isabs(path):
        exit_code, cwd, _ = exec_cmd(container_id, "pwd")
        if exit_code == 0 and cwd.strip():
            path = posixpath.join(cwd.strip(), path)
            logger.debug("Resolved relative path to %s", path)

    # Ensure parent directory exists inside the container
    parent_dir = posixpath.dirname(path)
    exec_cmd(container_id, f"mkdir -p '{parent_dir}'")

    # Write to a host temp file, then docker cp into the container
    if isinstance(content, str):
        content_bytes = content.encode("utf-8")
    else:
        content_bytes = content

    fd, tmp_path = tempfile.mkstemp()
    try:
        os.write(fd, content_bytes)
        os.close(fd)
        result = subprocess.run(
            ["docker", "cp", tmp_path, f"{container_id}:{path}"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            logger.warning("docker cp failed: %s", result.stderr)
        else:
            logger.debug("Wrote %d bytes to %s", len(content_bytes), path)
    finally:
        os.unlink(tmp_path)


def copy_from_container(container_id: str, src_path: str, dst_path: str) -> tuple[bool, str]:
    """Copy a file from container to host via ``docker cp``.

    Returns ``(success, message)``.
    """
    os.makedirs(os.path.dirname(dst_path) or ".", exist_ok=True)
    result = subprocess.run(
        ["docker", "cp", f"{container_id}:{src_path}", dst_path],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        msg = (result.stderr or result.stdout or "docker cp failed").strip()
        logger.warning(
            "docker cp from container failed (%s -> %s): %s",
            src_path, dst_path, msg,
        )
        return False, msg
    return True, "ok"


def start_patcher_containers(image: str, count: int) -> list[str]:
    """Start *count* lightweight containers for parallel Patcher agents.

    Each container runs ``sleep infinity`` and shares the same image as the
    main container so the source tree is available at ``/src``.  No build
    step is needed — the Patcher only reads and edits source files.

    Returns a list of container IDs.
    """
    ids: list[str] = []
    for i in range(count):
        cid = start_container(image)
        logger.info("Patcher container %d/%d: %s", i + 1, count, cid[:12])
        ids.append(cid)
    return ids


def stop_containers(container_ids: list[str]) -> None:
    """Stop and remove a batch of containers (best-effort)."""
    for cid in container_ids:
        stop_container(cid)


def stop_container(container_id: str) -> None:
    """Stop and remove a container."""
    client = _get_client()
    try:
        container = client.containers.get(container_id)
        container.stop(timeout=10)
        container.remove(force=True)
        logger.info("Stopped and removed container %s", container_id[:12])
    except docker.errors.NotFound:
        logger.warning("Container %s not found during cleanup", container_id[:12])
    except Exception as e:
        logger.warning("Error cleaning up container %s: %s", container_id[:12], e)


def build_project(container_id: str) -> tuple[bool, str]:
    """Run 'secb build' inside the container.

    Returns (success: bool, output: str).
    """
    exit_code, stdout, stderr = exec_cmd(
        container_id, "secb build", timeout=BUILD_TIMEOUT
    )
    combined = stdout + "\n" + stderr
    success = exit_code == 0
    if not success:
        logger.warning("Build failed (exit %d): %s", exit_code, combined[-500:])
    return success, combined


def run_repro(container_id: str) -> tuple[int, str]:
    """Run 'secb repro' and return (exit_code, combined_output).

    The output includes sanitizer messages if present.
    """
    exit_code, stdout, stderr = exec_cmd(container_id, "secb repro")
    combined = stdout + "\n" + stderr
    return exit_code, combined


def run_custom_repro(
    container_id: str,
    cmd: str,
) -> tuple[int, str]:
    """Run a custom repro command string.

    Args:
        container_id: The Docker container ID.
        cmd: The full command to execute (e.g. '/src/ffmpeg -i /testcase/variant_1.mp4 -f null -').

    Returns (exit_code, combined_output).
    """
    exit_code, stdout, stderr = exec_cmd(container_id, cmd)
    combined = stdout + "\n" + stderr
    return exit_code, combined


def apply_patch(container_id: str, patch_content: str) -> tuple[bool, str]:
    """Write a patch to /testcase/model_patch.diff and run 'secb patch'.

    If ``secb patch`` fails (strict git apply), falls back to
    ``git apply --3way`` which tolerates minor context differences.

    Returns (success: bool, output: str).
    """
    # Write the patch file
    write_file(container_id, "/testcase/model_patch.diff", patch_content)

    # Apply via secb patch
    exit_code, stdout, stderr = exec_cmd(container_id, "secb patch")
    combined = stdout + "\n" + stderr
    if exit_code == 0:
        return True, combined

    # Fallback: git apply --3way from repo root
    logger.info("secb patch failed, trying git apply --3way fallback")
    exit_code2, stdout2, stderr2 = exec_cmd(
        container_id,
        "cd /src && git apply --3way /testcase/model_patch.diff",
    )
    combined2 = stdout2 + "\n" + stderr2
    if exit_code2 == 0:
        logger.info("Fallback git apply --3way succeeded")
        return True, combined2

    logger.warning("Patch apply failed (both secb patch and --3way): %s", combined2[-500:])
    return False, combined + "\n--- fallback ---\n" + combined2


def reset_source(container_id: str) -> tuple[bool, str]:
    """Reset source code to original state using git checkout and git clean.

    Finds the source repo directory and runs git checkout + git clean to
    restore tracked files AND remove untracked files created by the Patcher.
    Returns (success: bool, output: str).
    """
    # Reset all modifications in /src and its sub-repos:
    # 1. git checkout -- .  => restore tracked file modifications
    # 2. git clean -fd      => remove untracked files and directories
    exit_code, stdout, stderr = exec_cmd(
        container_id,
        "cd /src && git checkout -- . && git clean -fd; "
        "for d in /src/*/; do "
        "  (cd \"$d\" && git checkout -- . && git clean -fd) 2>&1; "
        "done; "
        "echo 'reset done'"
    )
    combined = stdout + "\n" + stderr
    success = exit_code == 0
    if not success:
        logger.warning("reset_source failed (exit %d): %s", exit_code, combined[-500:])
    return success, combined


def get_image_name(instance_id: str) -> str:
    """Convert instance_id to Docker image name.

    E.g. 'gpac.cve-2023-42298' -> 'hwiwonlee/secb.eval.x86_64.gpac.cve-2023-42298:patch'
    """
    from config import DOCKER_IMAGE_PREFIX, DOCKER_IMAGE_TAG
    return f"{DOCKER_IMAGE_PREFIX}.{instance_id}:{DOCKER_IMAGE_TAG}"
