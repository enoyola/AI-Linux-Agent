"""Plan executor with allowlist enforcement and full command logging."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from storai.models import CommandResult, CommandSpec, Plan
from storai.safety import SafetyError, validate_command_allowlist, verify_device_safety
from storai.utils import ensure_log_file

WRITE_COMMANDS = {"parted", "mkfs.ext4", "mkfs.xfs", "mkdir", "mount", "umount", "apt", "apt-get", "dnf", "yum", "truncate", "tee"}
DEVICE_MUTATION_COMMANDS = {"parted", "mkfs.ext4", "mkfs.xfs"}


class Executor:
    def __init__(self, dry_run: bool = True, allow_writes: bool = False, log_file: Path | None = None) -> None:
        self.dry_run = dry_run
        self.allow_writes = allow_writes
        self.log_file = log_file or ensure_log_file()

    def _append_log(self, payload: dict) -> None:
        with self.log_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, default=str) + "\n")

    def _requires_root(self, spec: CommandSpec) -> bool:
        return spec.requires_root or spec.command in WRITE_COMMANDS

    def _assert_write_allowed(self, spec: CommandSpec) -> None:
        if spec.read_only:
            return
        if not self.allow_writes:
            raise SafetyError("Write execution is disabled (read-only default). Use --execute after review.")

    def _precheck_device_mutation(self, spec: CommandSpec) -> None:
        if spec.command not in DEVICE_MUTATION_COMMANDS:
            return
        for arg in spec.args:
            if not arg.startswith("/dev/"):
                continue

            report = verify_device_safety(arg)
            if report.ok:
                continue

            # Partition nodes may briefly lag after `parted` writes.
            if spec.command.startswith("mkfs.") and any("Device not found" in reason for reason in report.reasons):
                parent = self._partition_parent(arg)
                if parent:
                    parent_report = verify_device_safety(parent)
                    if parent_report.ok:
                        continue
                    raise SafetyError(
                        f"Device safety check failed for {arg}; parent {parent} unsafe: "
                        f"{', '.join(parent_report.reasons)}"
                    )

            raise SafetyError(f"Device safety check failed for {arg}: {', '.join(report.reasons)}")

    @staticmethod
    def _partition_parent(path: str) -> str | None:
        # /dev/sdc1 -> /dev/sdc
        m_std = re.match(r"^(/dev/[a-zA-Z]+)\d+$", path)
        if m_std:
            return m_std.group(1)

        # /dev/nvme0n1p1 -> /dev/nvme0n1
        m_nvme = re.match(r"^(/dev/nvme\d+n\d+)p\d+$", path)
        if m_nvme:
            return m_nvme.group(1)

        return None

    def run_spec(self, spec: CommandSpec) -> CommandResult:
        validate_command_allowlist(spec)
        self._assert_write_allowed(spec)
        self._precheck_device_mutation(spec)

        if self._requires_root(spec) and os.geteuid() != 0:
            raise PermissionError(f"Command requires root privileges: {spec.to_shell()}")

        if self.dry_run:
            result = CommandResult(command=spec.to_shell(), stdout="", stderr="", exit_code=0, executed=False, note="dry-run")
            self._append_log(result.model_dump())
            return result

        proc = subprocess.run(
            [spec.command, *spec.args],
            input=spec.stdin_text,
            capture_output=True,
            text=True,
            check=False,
        )
        result = CommandResult(
            command=spec.to_shell(),
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            executed=True,
        )
        self._append_log(result.model_dump())
        return result

    def execute_plan(self, plan: Plan, confirmation_text: str | None = None) -> list[CommandResult]:
        if not self.dry_run and plan.requires_confirmation_string and confirmation_text != plan.requires_confirmation_string:
            raise SafetyError(
                "Confirmation string mismatch. Expected: "
                f"{plan.requires_confirmation_string}"
            )

        results: list[CommandResult] = []
        for step in plan.steps:
            for cmd in step.commands:
                res = self.run_spec(cmd)
                results.append(res)
                if res.executed and res.exit_code != 0:
                    raise RuntimeError(f"Command failed: {res.command}\n{res.stderr}")
        return results
