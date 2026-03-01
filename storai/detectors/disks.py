"""Disk and mount discovery routines."""

from __future__ import annotations

from storai.utils import command_exists, run_cmd


def collect_block_context() -> dict[str, str]:
    context: dict[str, str] = {}

    commands: list[tuple[str, list[str]]] = [
        ("lsblk", ["lsblk", "-J", "-b", "-o", "NAME,SIZE,MODEL,SERIAL,TYPE,FSTYPE,MOUNTPOINTS,PATH,PKNAME"]),
        ("df", ["df", "-hT"]),
        ("df_inodes", ["df", "-ih"]),
        ("findmnt", ["findmnt", "-R"]),
    ]

    optional = {
        "pvs": ["pvs"],
        "vgs": ["vgs"],
        "lvs": ["lvs"],
    }

    for key, cmd in commands:
        out = run_cmd(cmd)
        context[key] = out.stdout if out.exit_code == 0 else f"ERROR: {out.stderr or out.stdout}"

    if command_exists("mdadm"):
        md = run_cmd(["mdadm", "--detail", "--scan"])
        context["mdadm"] = md.stdout if md.exit_code == 0 else md.stderr or md.stdout
    else:
        context["mdadm"] = "mdadm not available"

    for key, cmd in optional.items():
        if command_exists(cmd[0]):
            out = run_cmd(cmd)
            context[key] = out.stdout if out.exit_code == 0 else out.stderr or out.stdout
        else:
            context[key] = f"{cmd[0]} not available"

    return context
