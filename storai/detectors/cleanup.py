"""Cleanup recommendation heuristics."""

from __future__ import annotations

from storai.models import AdviceBundle, AdviceCategory, AdviceItem, SpaceAnalysis
from storai.utils import command_exists, distro_family


def _gb(nbytes: int) -> float:
    return round(nbytes / (1024**3), 2)


def build_cleanup_advice(space: SpaceAnalysis) -> AdviceBundle:
    items: list[AdviceItem] = []
    top_paths = {item.path: item.bytes_used for item in space.top_dirs}

    if distro_family() == "debian":
        items.append(
            AdviceItem(
                category=AdviceCategory.SAFE,
                title="Clean apt package cache",
                reasoning="APT caches old package files in /var/cache/apt/archives and can be cleaned safely.",
                commands=["sudo apt-get clean"],
            )
        )
    else:
        items.append(
            AdviceItem(
                category=AdviceCategory.SAFE,
                title="Clean dnf/yum package cache",
                reasoning="Package manager caches can usually be safely removed and re-downloaded if needed.",
                commands=["sudo dnf clean all"],
            )
        )

    if any(path.startswith("/var/log") for path in top_paths):
        est = sum(v for p, v in top_paths.items() if p.startswith("/var/log"))
        items.append(
            AdviceItem(
                category=AdviceCategory.SAFE,
                title="Vacuum journal logs",
                reasoning="Systemd journal logs often grow significantly; vacuuming old logs is low risk.",
                estimated_reclaim_gb=_gb(est),
                commands=["sudo journalctl --vacuum-time=7d", "sudo journalctl --vacuum-size=1G"],
            )
        )
        items.append(
            AdviceItem(
                category=AdviceCategory.CAUTION,
                title="Review rotated logs",
                reasoning="Large rotated logs may be removable, but active log files should not be truncated directly.",
                commands=["sudo find /var/log -type f -name '*.gz' -size +100M -print"],
            )
        )

    if command_exists("docker"):
        items.append(
            AdviceItem(
                category=AdviceCategory.CAUTION,
                title="Prune unused Docker data",
                reasoning="Pruning can remove unused images/layers/networks and possibly volumes if requested.",
                commands=["sudo docker system df", "sudo docker system prune -a"],
            )
        )

    for candidate in ["/var/lib/postgresql", "/var/lib/mysql", "/opt"]:
        if any(path.startswith(candidate) for path in top_paths):
            items.append(
                AdviceItem(
                    category=AdviceCategory.REVIEW,
                    title=f"Review data-heavy directory: {candidate}",
                    reasoning="Application and database directories may contain critical state; manual review required.",
                    commands=[f"sudo du -x -h --max-depth=2 {candidate} | sort -h"],
                )
            )

    if any(path.startswith("/home") for path in top_paths):
        est = sum(v for p, v in top_paths.items() if p.startswith("/home"))
        items.append(
            AdviceItem(
                category=AdviceCategory.REVIEW,
                title="Inspect user media or archives",
                reasoning="Large home directories often contain old backups, media, or VM images.",
                estimated_reclaim_gb=_gb(est),
                commands=["find /home -xdev -type f -size +1G -print"],
            )
        )

    items.append(
        AdviceItem(
            category=AdviceCategory.DANGEROUS,
            title="Do not run blind recursive deletes",
            reasoning="Commands like rm -rf on broad paths can destroy production systems.",
            commands=[],
        )
    )

    return AdviceBundle(
        summary="Generated deterministic cleanup recommendations from local heuristics.",
        items=items,
        findings={
            "top_dirs": [item.model_dump() for item in space.top_dirs],
            "top_files": [item.model_dump() for item in space.top_files],
            "inode": space.inode_report,
        },
        source="offline",
    )
