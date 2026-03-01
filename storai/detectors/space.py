"""Space usage analysis with one-filesystem default behavior."""

from __future__ import annotations

from pathlib import Path

from storai.models import SpaceAnalysis, SpaceItem
from storai.utils import run_cmd


def _parse_size_lines(lines: str, max_items: int) -> list[SpaceItem]:
    out: list[SpaceItem] = []
    for line in lines.splitlines()[:max_items]:
        if not line.strip():
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        try:
            size = int(parts[0])
        except ValueError:
            continue
        out.append(SpaceItem(path=parts[1], bytes_used=size))
    return out


def analyze_space(path: str, top_n: int = 10, one_filesystem: bool = True) -> SpaceAnalysis:
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    du_args = ["du", "-B1", "--max-depth=2", str(target)]
    if one_filesystem:
        du_args.insert(1, "-x")
    du = run_cmd(du_args)

    # Sorting is done in Python to avoid shell pipelines.
    dir_lines = [x for x in du.stdout.splitlines() if "\t" in x]
    dir_items = _parse_size_lines("\n".join(sorted(dir_lines, key=lambda x: int(x.split("\t", 1)[0]), reverse=True)), top_n)

    find_args = ["find", str(target), "-type", "f", "-printf", "%s\t%p\n"]
    if one_filesystem:
        find_args.insert(2, "-xdev")
    files = run_cmd(find_args, timeout=90)
    file_lines = [x for x in files.stdout.splitlines() if "\t" in x]
    file_items = _parse_size_lines("\n".join(sorted(file_lines, key=lambda x: int(x.split("\t", 1)[0]), reverse=True)), top_n)

    inode = run_cmd(["df", "-ih", str(target)])

    return SpaceAnalysis(
        target_path=str(target),
        one_filesystem=one_filesystem,
        top_dirs=dir_items,
        top_files=file_items,
        inode_report=inode.stdout,
        raw={
            "du": du.stdout,
            "find": files.stdout[:4000],
            "du_error": du.stderr,
            "find_error": files.stderr,
        },
    )
