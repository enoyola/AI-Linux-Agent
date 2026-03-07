"""Command allowlisting and storage safety checks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from storai.models import CommandSpec
from storai.utils import command_exists, run_cmd

ALLOWED_COMMANDS: set[str] = {
    "apt",
    "apt-get",
    "blkid",
    "cat",
    "containerd",
    "df",
    "dnf",
    "docker",
    "du",
    "echo",
    "find",
    "findmnt",
    "journalctl",
    "lsblk",
    "lvs",
    "mdadm",
    "mkdir",
    "mkfs.ext4",
    "mkfs.xfs",
    "mount",
    "parted",
    "podman",
    "pvs",
    "sort",
    "tail",
    "tee",
    "truncate",
    "umount",
    "vgs",
    "xargs",
    "yum",
}

ROOT_MOUNT_BLOCKLIST = {"/", "/boot", "/boot/efi"}
DEVICE_RE = re.compile(r"^/dev/[a-zA-Z0-9._/-]+$")


class SafetyError(RuntimeError):
    """Raised when a command or target fails safety checks."""


@dataclass(slots=True)
class DeviceIdentity:
    path: str
    name: str
    size: int
    model: str
    serial: str
    devtype: str
    mountpoints: list[str]
    fstype: str | None
    pkname: str | None


@dataclass(slots=True)
class DeviceSafetyReport:
    ok: bool
    identity: DeviceIdentity | None
    reasons: list[str]


def allowlist_table() -> list[str]:
    return sorted(ALLOWED_COMMANDS)


def validate_device_path(device: str) -> None:
    if not DEVICE_RE.match(device):
        raise SafetyError(f"Invalid device path: {device}")


def validate_command_allowlist(spec: CommandSpec) -> None:
    if spec.command not in ALLOWED_COMMANDS:
        raise SafetyError(f"Command '{spec.command}' is not allowlisted")


def _lsblk_json() -> dict[str, Any]:
    out = run_cmd(["lsblk", "-J", "-b", "-o", "NAME,SIZE,MODEL,SERIAL,TYPE,MOUNTPOINTS,FSTYPE,PKNAME,PATH"])
    if out.exit_code != 0:
        raise SafetyError(f"lsblk failed: {out.stderr or out.stdout}")
    return json.loads(out.stdout)


def _flatten(blockdevices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flat: list[dict[str, Any]] = []
    for dev in blockdevices:
        flat.append(dev)
        for child in dev.get("children", []) or []:
            flat.extend(_flatten([child]))
    return flat


def _as_identity(dev: dict[str, Any]) -> DeviceIdentity:
    mountpoints = [m for m in (dev.get("mountpoints") or []) if m]
    path = dev.get("path") or f"/dev/{dev.get('name')}"
    return DeviceIdentity(
        path=path,
        name=dev.get("name", ""),
        size=int(dev.get("size") or 0),
        model=str(dev.get("model") or "").strip(),
        serial=str(dev.get("serial") or "").strip(),
        devtype=str(dev.get("type") or "").strip(),
        mountpoints=mountpoints,
        fstype=dev.get("fstype"),
        pkname=dev.get("pkname"),
    )


def device_inventory() -> dict[str, DeviceIdentity]:
    if not command_exists("lsblk"):
        raise SafetyError("lsblk not found")
    raw = _lsblk_json()
    all_devs = _flatten(raw.get("blockdevices", []))
    inv = {}
    for dev in all_devs:
        ident = _as_identity(dev)
        inv[ident.path] = ident
    return inv


def _parent_path(identity: DeviceIdentity) -> str | None:
    if identity.pkname:
        return f"/dev/{identity.pkname}"
    return None


def verify_device_safety(device: str) -> DeviceSafetyReport:
    validate_device_path(device)
    reasons: list[str] = []
    inv = device_inventory()
    ident = inv.get(device)
    if not ident:
        return DeviceSafetyReport(ok=False, identity=None, reasons=[f"Device not found: {device}"])

    if ident.mountpoints:
        reasons.append(f"Device has mountpoints: {', '.join(ident.mountpoints)}")

    # For whole disks, also inspect child partitions (pkname == disk name).
    if ident.devtype == "disk":
        children = [d for d in inv.values() if d.pkname == ident.name]
        child_mounts = [mp for d in children for mp in d.mountpoints]
        if child_mounts:
            reasons.append(f"Disk has mounted child partitions: {', '.join(sorted(set(child_mounts)))}")
        if any(mp in ROOT_MOUNT_BLOCKLIST for mp in child_mounts):
            reasons.append("Disk contains protected mounted partitions (/, /boot, or /boot/efi)")

    parent = inv.get(_parent_path(ident) or "")
    if parent and any(mp in ROOT_MOUNT_BLOCKLIST for mp in parent.mountpoints):
        reasons.append(f"Parent disk {parent.path} hosts protected mountpoints")

    if any(mp in ROOT_MOUNT_BLOCKLIST for mp in ident.mountpoints):
        reasons.append("Target includes protected mountpoints (/, /boot, or /boot/efi)")

    pvs = run_cmd(["pvs", "--noheadings", "-o", "pv_name"]) if command_exists("pvs") else None
    if pvs and pvs.exit_code == 0 and device in pvs.stdout:
        reasons.append("Device appears to be an LVM physical volume")

    md = run_cmd(["mdadm", "--examine", device]) if command_exists("mdadm") else None
    if md and md.exit_code == 0 and "Raid Level" in md.stdout:
        reasons.append("Device appears to be part of RAID metadata")

    return DeviceSafetyReport(ok=not reasons, identity=ident, reasons=reasons)


def confirmation_phrase_for_format(device: str) -> str:
    return f"CONFIRM FORMAT {device}"
