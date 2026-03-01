# StorAI - Linux Storage AI Agent

Production-oriented Linux storage assistant with strict planner/executor separation and safety-first defaults.

## Key Safety Guarantees
- Default behavior is read-only.
- Plans are always shown before execution.
- Executor only allows explicitly allowlisted commands.
- LLM output is JSON-only, schema-validated via Pydantic.
- Invalid LLM output automatically falls back to offline heuristics.
- Before destructive disk actions, device checks enforce:
  - identity verification (`NAME+SIZE+MODEL+SERIAL` via `lsblk`)
  - not mounted (`findmnt` / `lsblk` mountpoints)
  - not protected (`/`, `/boot`, `/boot/efi`)
  - not LVM PV / RAID member where detectable
- Write actions require explicit `--execute` and confirmation phrase.
- Command execution logs are written to `~/.storai/logs/run-YYYYMMDD-HHMMSS.log` with stdout/stderr/exit code/timestamp.

## Install
```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .[test]
# Optional AI providers:
pip install -e .[ai]
```

## CLI
```bash
storai --mode offline scan
storai --mode offline space /
storai --mode offline advise --path /
storai plan mount --device /dev/sdb --mountpoint /data --fstype ext4 --out mount-plan.json
storai apply mount-plan.json --execute --dry-run=false
```

Global flags:
- `--mode [offline|ai]` (default `offline`)
- `--provider [openai|anthropic]` (default `openai`, AI mode only)
- `--model <string>`
- `--temperature <float>` (default `0.2`)
- `--max-tokens <int>`

## AI Mode
- OpenAI: set `OPENAI_API_KEY`
- Anthropic: set `ANTHROPIC_API_KEY`

LLM commands are advisory only. Executor still enforces allowlist + safety checks.

## Allowlist (core)
| Command |
|---|
| lsblk |
| df |
| du |
| find |
| findmnt |
| pvs / vgs / lvs |
| mdadm |
| parted |
| mkfs.ext4 / mkfs.xfs |
| mkdir |
| mount / umount |
| blkid |
| journalctl |
| apt / apt-get / dnf / yum |
| docker / podman |
| truncate |

## Sample Output: `storai scan`
```text
lsblk panel + df panel output with block devices, filesystems, mountpoints, and types.
```

## Sample Output: `storai advise --path /`
```text
# Storage Advice
Generated deterministic cleanup recommendations from local heuristics.

## [SAFE] Clean apt package cache
APT caches old package files in /var/cache/apt/archives and can be cleaned safely.
Commands:
- sudo apt-get clean

## [SAFE] Vacuum journal logs
Systemd journal logs often grow significantly; vacuuming old logs is low risk.
Commands:
- sudo journalctl --vacuum-time=7d
- sudo journalctl --vacuum-size=1G
```

## Sample Output: `storai plan mount ...`
```text
# Plan: Prepare and mount /dev/sdb at /data (ext4)

## Warnings
- Target device identity verified: NAME=sdb SIZE=... MODEL=... SERIAL=...

## Steps
- verify (lsblk/findmnt/pvs/mdadm)
- partition (parted mklabel/mkpart)
- makefs (mkfs.ext4)
- mount (mkdir/mount)
- persist (blkid/fstab preview/mount -a/findmnt)

Required confirmation: CONFIRM FORMAT /dev/sdb
Rollback:
- sudo umount /data
- sudo sed -i '\\|/data|d' /etc/fstab
- sudo parted -s /dev/sdb rm 1
```

## Tests
```bash
pytest
```

## Notes
- The tool does not assume root. It raises clear errors when a command needs elevated privileges.
- By default, `storai apply` exits without changes unless `--execute` is provided.
- Keep `--dry-run` enabled until you have verified every planned command.
