"""测试拥有的回环部署与进程启动；不读取日常多机配置。"""

from __future__ import annotations

import socket
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

import yaml

from secure_control.execution.lan_config import load_lan_config

ROOT = Path(__file__).resolve().parents[1]


def free_ports() -> tuple[int, int, int]:
    """同时保留三个探测 socket，返回互不重复的回环端口。"""
    sockets = []
    try:
        for _ in range(3):
            item = socket.socket()
            sockets.append(item)
            item.bind(("127.0.0.1", 0))
        return tuple(item.getsockname()[1] for item in sockets)
    finally:
        for item in sockets:
            item.close()


def loopback_deployment(root: Path) -> dict[str, Path]:
    """生成可立即验证的独立明文角色配置，数值仍来自 canonical 文件。"""
    topology = root / "topology.yaml"
    topology.write_text(yaml.safe_dump({
        "version": 1,
        "identities": {role: f"{role.lower()}.secure-control.test"
                       for role in ("Client", "P1", "P2")},
        **{name: {"bind": "127.0.0.1", "host": "127.0.0.1", "port": port}
           for name, port in zip(("p1_client", "p2_client", "p1_peer"),
                                 free_ports(), strict=True)},
    }, sort_keys=False), encoding="utf-8")
    paths = {}
    for role, name in (("P1", "lab-p1.example.yaml"), ("P2", "lab-p2.example.yaml"),
                       ("Client", "lab-client-continuous.example.yaml")):
        data = {
            "role": role, "transport": "insecure_tcp", "topology": str(topology),
            **({"experiment": str(ROOT / "configs/paper_pid_lan.example.yaml")}
               if role == "Client" else {}),
            "timeouts": {"startup": 180, "step": 30,
                         **({"idle": 30} if role == "Client" else {}), "shutdown": 5},
        }
        path = root / name
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        load_lan_config(path, role)
        paths[role] = path
    return paths


def select_experiment(client: Path, profile: Path) -> None:
    """结构化切换测试场景，不依赖已有 YAML 的路径、缩进或键顺序。"""
    data = yaml.safe_load(client.read_text(encoding="utf-8"))
    data.pop("controller", None)
    data["experiment"] = str(profile.resolve())
    client.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    load_lan_config(client, "Client")


def role_command(role: str, config: Path, *, console: bool = False) -> list[str]:
    """普通联调复用当前解释器；console=True 专门验证安装后的命令入口。"""
    entry = (["uv", "run", "secure-control"] if console else
             [sys.executable, "-m", "secure_control.experiments.lan_runner"])
    return [*entry, role.lower(), "--config", str(config)]


def run_role(role: str, config: Path, *, console: bool = False) -> subprocess.Popen[str]:
    """创建一个由调用测试拥有的真实角色进程。"""
    return subprocess.Popen(
        role_command(role, config, console=console), cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def reap_processes(processes: Iterable[subprocess.Popen[str]]) -> None:
    """仅回收当前测试拥有的子进程，并关闭管道；不清理其他 Python PID。"""
    for process in processes:
        if process.poll() is None:
            # Windows 下 uv 和 .venv 的 Python 都可能是包装进程；只终止
            # 本测试拥有的 PID 子树，避免遗留真正执行代码的子进程。
            if sys.platform == "win32" and getattr(process, "pid", None) is not None:
                result = subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                if result.returncode != 0 and process.poll() is None:
                    raise RuntimeError(f"无法回收测试拥有的 PID {process.pid}: {result.stderr}")
            else:
                process.kill()
        process.communicate(timeout=5)


def start_processes(commands: list[list[str]]) -> list[subprocess.Popen[str]]:
    """从第一个资源创建起保护部分 setup；后续清理由调用测试负责。"""
    processes = []
    try:
        for command in commands:
            processes.append(subprocess.Popen(
                command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ))
        return processes
    except BaseException:
        reap_processes(processes)
        raise
