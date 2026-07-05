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
from storai.safety import SafetyError, confirmation_phrase_for_format, device_inventory, verify_device_safety
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

    def suggest_safe_disk(self, min_size_gb: int = 1) -> str:
        inv = device_inventory()
        min_bytes = min_size_gb * (1024**3)
        candidates: list[str] = []

        for path, ident in inv.items():
            if ident.devtype != "disk":
                continue
            if ident.size < min_bytes:
                continue
            if ident.mountpoints:
                continue
            if ident.fstype:
                continue
            report = verify_device_safety(path)
            if report.ok:
                candidates.append(path)

        if not candidates:
            raise SafetyError(f"No safe unmounted whole disk found with at least {min_size_gb} GiB free")
        return sorted(candidates)[0]

    def _validate_disk(self, device: str, size_gb: int | None) -> tuple[list[str], int]:
        safety = verify_device_safety(device)
        warnings: list[str] = []
        if not safety.ok:
            raise SafetyError(f"Device failed safety checks: {', '.join(safety.reasons)}")

        identity = safety.identity
        if identity is None:
            raise SafetyError(f"Device not found: {device}")
        if identity.devtype != "disk":
            raise SafetyError(f"Target must be a whole disk (type=disk). Got type={identity.devtype}")
        if identity.fstype:
            raise SafetyError(f"Target already has filesystem signature: {identity.fstype}")
        if size_gb is not None and identity.size < size_gb * (1024**3):
            raise SafetyError(f"Device {device} is smaller than requested size {size_gb} GiB")

        warnings.append(
            "Target device identity verified: "
            f"NAME={identity.name} SIZE={identity.size} MODEL={identity.model or '-'} SERIAL={identity.serial or '-'}"
        )
        return warnings, identity.size

    def plan_mount(self, device: str, mountpoint: str, fstype: str, size_gb: int | None = None) -> Plan:
        if fstype not in {"ext4", "xfs"}:
            raise ValueError("fstype must be ext4 or xfs")

        warnings, _ = self._validate_disk(device, size_gb)
        fs_cmd = "mkfs.ext4" if fstype == "ext4" else "mkfs.xfs"
        part = f"{device}1"
        uuid_ref = f"UUID=<from blkid {part}>"

        partition_end = "100%" if size_gb is None else f"{size_gb}GiB"
        partition_title = "Partition disk GPT with one full partition"
        partition_rationale = "Create GPT and a single data partition across full disk."
        if size_gb is not None:
            partition_title = f"Partition disk GPT with one {size_gb}GiB partition"
            partition_rationale = f"Create GPT and a single {size_gb}GiB partition from start of disk."

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
                title=partition_title,
                rationale=partition_rationale,
                risk=RiskLevel.HIGH,
                commands=[
                    CommandSpec(command="parted", args=["-s", device, "mklabel", "gpt"], rationale="Create GPT label.", read_only=False, requires_root=True),
                    CommandSpec(command="parted", args=["-s", device, "mkpart", "primary", fstype, "0%", partition_end], rationale="Create partition.", read_only=False, requires_root=True),
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
                    CommandSpec(command="echo", args=[f"UUID=<from blkid {part}> {mountpoint} {fstype} defaults,nofail 0 2"], rationale="Preview fstab line before editing.", read_only=True),
                    CommandSpec(command="tee", args=["-a", "/etc/fstab"], stdin_text=f"{uuid_ref} {mountpoint} {fstype} defaults,nofail 0 2\n", rationale="Append UUID-based entry to /etc/fstab.", read_only=False, requires_root=True),
                    CommandSpec(command="mount", args=["-a"], rationale="Validate fstab syntax and mountability.", read_only=False, requires_root=True),
                    CommandSpec(command="findmnt", args=[mountpoint], rationale="Validate mount is active.", read_only=True),
                ],
            ),
        ]

        size_note = "full disk" if size_gb is None else f"{size_gb}GiB"
        return Plan(
            goal=f"Prepare and mount {device} at {mountpoint} ({fstype}, {size_note})",
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

    def plan_lvm(self, device: str, mountpoint: str, fstype: str, size_gb: int | None = None, vg_name: str = "data-vg", lv_name: str = "data-lv") -> Plan:
        if fstype not in {"ext4", "xfs"}:
            raise ValueError("fstype must be ext4 or xfs")

        warnings, _ = self._validate_disk(device, size_gb)
        part = f"{device}1"
        lv_path = f"/dev/{vg_name}/{lv_name}"
        fs_cmd = "mkfs.ext4" if fstype == "ext4" else "mkfs.xfs"

        partition_end = "100%" if size_gb is None else f"{size_gb}GiB"
        lvcreate_args = ["-l", "100%FREE", "-n", lv_name, vg_name] if size_gb is None else ["-L", f"{size_gb}G", "-n", lv_name, vg_name]

        steps = [
            PlanStep(
                id="verify",
                title="Verify target disk and existing LVM state",
                rationale="Confirm disk safety and collect current PV/VG/LV state.",
                risk=RiskLevel.HIGH,
                commands=[
                    CommandSpec(command="lsblk", args=["-o", "NAME,SIZE,MODEL,SERIAL,TYPE,MOUNTPOINTS,PATH"], rationale="Verify identity.", read_only=True),
                    CommandSpec(command="findmnt", args=["-R"], rationale="Verify mount state.", read_only=True),
                    CommandSpec(command="pvs", args=[], rationale="Current PVs.", read_only=True),
                    CommandSpec(command="vgs", args=[], rationale="Current VGs.", read_only=True),
                    CommandSpec(command="lvs", args=[], rationale="Current LVs.", read_only=True),
                ],
            ),
            PlanStep(
                id="partition",
                title="Partition disk for LVM",
                rationale="Create GPT and an LVM partition on target disk.",
                risk=RiskLevel.HIGH,
                commands=[
                    CommandSpec(command="parted", args=["-s", device, "mklabel", "gpt"], rationale="Create GPT label.", read_only=False, requires_root=True),
                    CommandSpec(command="parted", args=["-s", device, "mkpart", "primary", "0%", partition_end], rationale="Create LVM partition.", read_only=False, requires_root=True),
                ],
            ),
            PlanStep(
                id="lvm",
                title="Create PV, VG, and LV",
                rationale="Initialize LVM stack before filesystem creation.",
                risk=RiskLevel.HIGH,
                commands=[
                    CommandSpec(command="pvcreate", args=[part], rationale="Initialize physical volume.", read_only=False, requires_root=True),
                    CommandSpec(command="vgcreate", args=[vg_name, part], rationale="Create volume group.", read_only=False, requires_root=True),
                    CommandSpec(command="lvcreate", args=lvcreate_args, rationale="Create logical volume.", read_only=False, requires_root=True),
                ],
            ),
            PlanStep(
                id="makefs",
                title="Create filesystem on logical volume",
                rationale="Initialize selected filesystem on LV.",
                risk=RiskLevel.HIGH,
                commands=[
                    CommandSpec(command=fs_cmd, args=["-F", lv_path] if fstype == "ext4" else ["-f", lv_path], rationale="Create filesystem.", read_only=False, requires_root=True),
                ],
            ),
            PlanStep(
                id="mount",
                title="Create mountpoint and mount LV",
                rationale="Mount logical volume to target path.",
                risk=RiskLevel.MEDIUM,
                commands=[
                    CommandSpec(command="mkdir", args=["-p", mountpoint], rationale="Create mount directory.", read_only=False, requires_root=True),
                    CommandSpec(command="mount", args=[lv_path, mountpoint], rationale="Attach filesystem.", read_only=False, requires_root=True),
                ],
            ),
            PlanStep(
                id="persist",
                title="Persist in fstab and validate",
                rationale="Use UUID in fstab and validate mount config.",
                risk=RiskLevel.MEDIUM,
                commands=[
                    CommandSpec(command="blkid", args=["-s", "UUID", "-o", "value", lv_path], rationale="Read UUID for fstab.", read_only=True),
                    CommandSpec(command="echo", args=[f"UUID=<from blkid {lv_path}> {mountpoint} {fstype} defaults,nofail 0 2"], rationale="Preview fstab line.", read_only=True),
                    CommandSpec(command="tee", args=["-a", "/etc/fstab"], stdin_text=f"UUID=<from blkid {lv_path}> {mountpoint} {fstype} defaults,nofail 0 2\n", rationale="Append fstab entry.", read_only=False, requires_root=True),
                    CommandSpec(command="mount", args=["-a"], rationale="Validate fstab and mountability.", read_only=False, requires_root=True),
                    CommandSpec(command="findmnt", args=[mountpoint], rationale="Validate active mount.", read_only=True),
                ],
            ),
        ]

        size_note = "all free space" if size_gb is None else f"{size_gb}GiB"
        return Plan(
            goal=f"Prepare LVM ({vg_name}/{lv_name}) and mount at {mountpoint} ({fstype}, {size_note}) on {device}",
            steps=steps,
            warnings=warnings,
            rollback=[
                f"sudo umount {mountpoint}",
                f"sudo sed -i '\\|{mountpoint}|d' /etc/fstab",
                f"sudo lvremove -y {lv_path}",
                f"sudo vgremove -y {vg_name}",
                f"sudo pvremove -y {part}",
                f"sudo parted -s {device} rm 1",
            ],
            requires_confirmation_string=confirmation_phrase_for_format(device),
            source="offline",
        )
