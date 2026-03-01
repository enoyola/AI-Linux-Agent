"""Reporting helpers for markdown and json output."""

from __future__ import annotations

import json

from storai.models import AdviceBundle, Plan, SpaceAnalysis


def plan_to_markdown(plan: Plan) -> str:
    lines = [f"# Plan: {plan.goal}", "", "## Warnings"]
    if plan.warnings:
        lines.extend([f"- {w}" for w in plan.warnings])
    else:
        lines.append("- None")

    lines.append("\n## Steps")
    for step in plan.steps:
        lines.append(f"### {step.id}: {step.title} ({step.risk.value})")
        lines.append(step.rationale)
        for cmd in step.commands:
            lines.append(f"- `{cmd.to_shell()}`")

    lines.append("\n## Rollback")
    lines.extend([f"- `{cmd}`" for cmd in plan.rollback] or ["- None"])
    if plan.requires_confirmation_string:
        lines.append(f"\nRequired confirmation: `{plan.requires_confirmation_string}`")
    return "\n".join(lines)


def advice_to_markdown(advice: AdviceBundle) -> str:
    lines = ["# Storage Advice", "", advice.summary, ""]
    for item in advice.items:
        lines.append(f"## [{item.category.value}] {item.title}")
        lines.append(item.reasoning)
        if item.estimated_reclaim_gb is not None:
            lines.append(f"Estimated reclaim: {item.estimated_reclaim_gb} GB")
        if item.commands:
            lines.append("Commands:")
            lines.extend([f"- `{c}`" for c in item.commands])
        lines.append("")
    return "\n".join(lines)


def space_to_markdown(space: SpaceAnalysis) -> str:
    lines = [f"# Space Analysis: {space.target_path}", "", f"One filesystem: {space.one_filesystem}", "", "## Top Directories"]
    for item in space.top_dirs:
        lines.append(f"- {item.path}: {item.bytes_used} bytes")
    lines.append("\n## Top Files")
    for item in space.top_files:
        lines.append(f"- {item.path}: {item.bytes_used} bytes")
    lines.append("\n## Inodes")
    lines.append(f"```\n{space.inode_report}\n```")
    return "\n".join(lines)


def to_json(data: object) -> str:
    if hasattr(data, "model_dump"):
        data = data.model_dump()
    return json.dumps(data, indent=2, default=str)
