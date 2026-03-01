"""Shared utility helpers for command execution and platform checks."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(slots=True)
class RunOutput:
    command: str
    stdout: str
    stderr: str
    exit_code: int


def run_cmd(args: list[str], timeout: int = 30) -> RunOutput:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    return RunOutput(
        command=" ".join(args),
        stdout=proc.stdout.strip(),
        stderr=proc.stderr.strip(),
        exit_code=proc.returncode,
    )


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def read_os_release() -> dict[str, str]:
    out: dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        out[key] = value.strip().strip('"')
    return out


def distro_family() -> str:
    data = read_os_release()
    like = data.get("ID_LIKE", "").lower()
    ident = data.get("ID", "").lower()
    if any(x in like for x in ["rhel", "fedora", "centos"]) or ident in {"rhel", "fedora", "centos", "rocky", "almalinux"}:
        return "rhel"
    return "debian"


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def ensure_log_file() -> Path:
    root = Path(os.path.expanduser("~/.storai/logs"))
    root.mkdir(parents=True, exist_ok=True)
    return root / f"run-{now_stamp()}.log"


def json_pretty(data: object) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def host_meta() -> dict[str, str]:
    return {
        "hostname": platform.node(),
        "kernel": platform.release(),
        "platform": platform.platform(),
    }
