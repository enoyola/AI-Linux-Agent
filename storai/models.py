"""Core data models used by planner, executor, and reporting."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AdviceCategory(str, Enum):
    SAFE = "SAFE"
    CAUTION = "CAUTION"
    REVIEW = "REVIEW"
    DANGEROUS = "DANGEROUS"


class CommandSpec(BaseModel):
    """A single command in a plan step."""

    command: str
    args: list[str] = Field(default_factory=list)
    rationale: str = ""
    read_only: bool = True
    requires_root: bool = False
    stdin_text: str | None = None

    @field_validator("command")
    @classmethod
    def validate_command_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("command cannot be empty")
        if "/" in value:
            raise ValueError("command must be a binary name, not a path")
        return value

    def to_shell(self) -> str:
        base = " ".join([self.command, *self.args]).strip()
        if self.stdin_text is not None:
            return f"{base}  # stdin provided"
        return base


class PlanStep(BaseModel):
    id: str
    title: str
    rationale: str
    risk: RiskLevel = RiskLevel.LOW
    commands: list[CommandSpec] = Field(default_factory=list)


class Plan(BaseModel):
    goal: str
    steps: list[PlanStep]
    warnings: list[str] = Field(default_factory=list)
    rollback: list[str] = Field(default_factory=list)
    requires_confirmation_string: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "offline"


class AdviceItem(BaseModel):
    category: AdviceCategory
    title: str
    reasoning: str
    estimated_reclaim_gb: float | None = None
    commands: list[str] = Field(default_factory=list)


class AdviceBundle(BaseModel):
    summary: str
    items: list[AdviceItem] = Field(default_factory=list)
    findings: dict[str, Any] = Field(default_factory=dict)
    source: str = "offline"


class CommandResult(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    command: str
    stdout: str
    stderr: str
    exit_code: int
    executed: bool = True
    note: str | None = None


class SpaceItem(BaseModel):
    path: str
    bytes_used: int


class SpaceAnalysis(BaseModel):
    target_path: str
    one_filesystem: bool = True
    top_dirs: list[SpaceItem] = Field(default_factory=list)
    top_files: list[SpaceItem] = Field(default_factory=list)
    inode_report: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)
