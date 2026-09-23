"""三台独立主机的单步 LAN 试验命令入口；不管理远端进程。"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from secure_control.execution.lan_config import load_lan_config
from secure_control.execution.lan_runtime import run_client_single_step, run_party_single_step
from secure_control.execution.lan_transport import (
    LanConnectionError,
    LanIdentityError,
    LanTimeoutError,
)
from secure_control.execution.localhost_codec import LocalhostCodecError
from secure_control.execution.localhost_transport import (
    LocalhostTransportDisconnected,
    LocalhostTransportTimeout,
)
from secure_control.scenarios.hvac.integration import HvacScenario


def _failure(role: str, code: int, category: str, error: Exception) -> int:
    print(
        json.dumps(
            {
                "status": "failed",
                "role": role,
                "pid": os.getpid(),
                "category": category,
                "error_type": type(error).__name__,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return code


def cli() -> None:
    """pyproject 命令入口：配置错误 2、连接 3、身份/协议 4、不确定/超时 5。"""
    raise SystemExit(_run())


def _run() -> int:
    parser = argparse.ArgumentParser(
        prog="secure-control", description="One-shot authenticated LAN trial"
    )
    commands = parser.add_subparsers(dest="role", required=True)
    for role in ("p1", "p2", "client"):
        command = commands.add_parser(role)
        command.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    role = {"p1": "P1", "p2": "P2", "client": "Client"}[args.role]
    try:
        config = load_lan_config(args.config, role)
        trial = (
            HvacScenario(config.controller_config).build_lan_single_step()
            if role == "Client"
            else None
        )
    except (ValueError, TypeError, OSError) as error:
        return _failure(role, 2, "configuration", error)
    try:
        result = (
            run_client_single_step(config, trial)
            if role == "Client"
            else run_party_single_step(config)
        )
    except LanConnectionError as error:
        return _failure(role, 3, "connection", error)
    except (LanIdentityError, LocalhostCodecError, ValueError, TypeError) as error:
        return _failure(role, 4, "identity_or_protocol", error)
    except (
        LanTimeoutError,
        LocalhostTransportTimeout,
        LocalhostTransportDisconnected,
        TimeoutError,
        RuntimeError,
        OSError,
    ) as error:
        return _failure(role, 5, "uncertain_or_disconnected", error)
    except Exception as error:  # noqa: BLE001 - CLI 不把意外异常的 payload/traceback 输出到日志
        return _failure(role, 5, "uncertain_or_disconnected", error)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False))
    return 0
