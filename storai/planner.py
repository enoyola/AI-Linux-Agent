"""Planner component: builds context, creates plans, and handles AI fallback."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from storai.detectors.disks import collect_block_context
from storai.detectors.space import analyze_space
from storai.llm_client import (
    AnthropicClient,
    LLMClient,
    LLMOutputError,
    OfflineRulesClient,
    OpenAIClient,
)
from storai.models import AdviceBundle, CommandSpec, Plan, PlanStep, RiskLevel
from storai.safety import SafetyError, confirmation_phrase_for_format, verify_device_safety
from storai.utils import host_meta, read_os_release


@dataclass(slots=True)
class PlannerConfig:
    mode: str = "offline"
    provider: str = "openai"
    model: str | None = None
    temperature: float = 0.2
    max_tokens: int = 1200


class Planner:
    def __init__(self, config: PlannerConfig) -> None:
        self.config = config
        self.offline = OfflineRulesClient()
        self.client = self._select_client()

    def _select_client(self) -> LLMClient:
        if self.config.mode == "offline":
            return self.offline
        if self.config.provider == "anthropic":
            return AnthropicClient(model=self.config.model, temperature=self.config.temperature, max_tokens=self.config.max_tokens)
        return OpenAIClient(model=self.config.model, temperature=self.config.temperature, max_tokens=self.config.max_tokens)

    def build_context(self, target_path: str | None = None, top_n: int = 10) -> dict[str, Any]:
        ctx: dict[str, Any] = {
            "host": host_meta(),
            "os_release": read_os_release(),
            "block": collect_block_context(),
        }
        if target_path:
            space = analyze_space(target_path, top_n=top_n, one_filesystem=True)
            ctx["space_analysis"] = space.model_dump()
            ctx["space_analysis_obj"] = space
            ctx["detected_services"] = {
                "docker": "docker" in ctx["block"].get("df", "").lower() or "docker" in ctx["block"].get("findmnt", "").lower(),
                "containerd": "containerd" in ctx["block"].get("findmnt", "").lower(),
                "journald": True,
            }
        return ctx

    def advise(self, context: dict[str, Any]) -> tuple[AdviceBundle, list[str]]:
        warnings: list[str] = []
        if self.config.mode == "offline":
            return self.offline.generate_advice(context), warnings
        try:
            return self.client.generate_advice(context), warnings
        except LLMOutputError as exc:
            warnings.append(f"AI output invalid; fallback to offline rules: {exc}")
            return self.offline.generate_advice(context), warnings

    def plan_mount(self, device: str, mountpoint: str, fstype: str) -> Plan:
        safety = verify_device_safety(device)
        warnings: list[str] = []
        if not safety.ok:
            raise SafetyError(f"Device failed safety checks: {', '.join(safety.reasons)}")
        if fstype not in {"ext4", "xfs"}:
            raise ValueError("fstype must be ext4 or xfs")

        fs_cmd = "mkfs.ext4" if fstype == "ext4" else "mkfs.xfs"
        part = f"{device}1"
        uuid_ref = f"UUID=<from blkid {part}>"

        identity = safety.identity
        if identity:
            if identity.devtype != "disk":
                raise SafetyError(f"Target must be a whole disk (type=disk). Got type={identity.devtype}")
            if identity.fstype:
                raise SafetyError(f"Target already has filesystem signature: {identity.fstype}")
            warnings.append(
                "Target device identity verified: "
                f"NAME={identity.name} SIZE={identity.size} MODEL={identity.model or '-'} SERIAL={identity.serial or '-'}"
            )

        steps = [
            PlanStep(
                id="verify",
                title="Verify target disk safety",
                rationale="Collect immutable identifiers and confirm device is not mounted, not root/boot, and not in LVM/RAID.",
                risk=RiskLevel.HIGH,
                commands=[
                    CommandSpec(command="lsblk", args=["-o", "NAME,SIZE,MODEL,SERIAL,TYPE,MOUNTPOINTS,PATH"], rationale="Verify identity.", read_only=True),
                    CommandSpec(command="findmnt", args=["-R"], rationale="Verify mount state.", read_only=True),
                    CommandSpec(command="pvs", args=[], rationale="Check LVM membership.", read_only=True),
                    CommandSpec(command="mdadm", args=["--detail", "--scan"], rationale="Check RAID arrays.", read_only=True),
                ],
            ),
            PlanStep(
                id="partition",
                title="Partition disk GPT with one full partition",
                rationale="Create GPT and a single data partition across full disk.",
                risk=RiskLevel.HIGH,
                commands=[
                    CommandSpec(command="parted", args=["-s", device, "mklabel", "gpt"], rationale="Create GPT label.", read_only=False, requires_root=True),
                    CommandSpec(command="parted", args=["-s", device, "mkpart", "primary", fstype, "0%", "100%"], rationale="Create partition.", read_only=False, requires_root=True),
                ],
            ),
            PlanStep(
                id="makefs",
                title="Create filesystem",
                rationale="Initialize filesystem on newly created partition.",
                risk=RiskLevel.HIGH,
                commands=[
                    CommandSpec(command=fs_cmd, args=["-F", part] if fstype == "ext4" else ["-f", part], rationale="Create filesystem.", read_only=False, requires_root=True),
                ],
            ),
            PlanStep(
                id="mount",
                title="Create mountpoint and mount",
                rationale="Ensure mountpoint exists and mount new filesystem.",
                risk=RiskLevel.MEDIUM,
                commands=[
                    CommandSpec(command="mkdir", args=["-p", mountpoint], rationale="Create mount directory.", read_only=False, requires_root=True),
                    CommandSpec(command="mount", args=[part, mountpoint], rationale="Attach filesystem.", read_only=False, requires_root=True),
                ],
            ),
            PlanStep(
                id="persist",
                title="Persist in fstab and validate",
                rationale="Use UUID-based fstab entry and verify mount config.",
                risk=RiskLevel.MEDIUM,
                commands=[
                    CommandSpec(command="blkid", args=["-s", "UUID", "-o", "value", part], rationale="Read UUID for fstab.", read_only=True),
                    CommandSpec(command="echo", args=[f"{uuid_ref} {mountpoint} {fstype} defaults,nofail 0 2"], rationale="Preview fstab line before editing.", read_only=True),
                    CommandSpec(
                        command="tee",
                        args=["-a", "/etc/fstab"],
                        stdin_text=f"{uuid_ref} {mountpoint} {fstype} defaults,nofail 0 2\n",
                        rationale="Append UUID-based entry to /etc/fstab.",
                        read_only=False,
                        requires_root=True,
                    ),
                    CommandSpec(command="mount", args=["-a"], rationale="Validate fstab syntax and mountability.", read_only=False, requires_root=True),
                    CommandSpec(command="findmnt", args=[mountpoint], rationale="Validate mount is active.", read_only=True),
                ],
            ),
        ]

        return Plan(
            goal=f"Prepare and mount {device} at {mountpoint} ({fstype})",
            steps=steps,
            warnings=warnings,
            rollback=[
                f"sudo umount {mountpoint}",
                f"sudo sed -i '\\|{mountpoint}|d' /etc/fstab",
                f"sudo parted -s {device} rm 1",
            ],
            requires_confirmation_string=confirmation_phrase_for_format(device),
            source="offline",
        )
