"""Typer CLI entrypoint for storai."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel

from storai.executor import Executor
from storai.models import Plan
from storai.planner import Planner, PlannerConfig
from storai.reporting import advice_to_markdown, plan_to_markdown, space_to_markdown, to_json

app = typer.Typer(help="Linux Storage AI Agent")
plan_app = typer.Typer(help="Plan operations")
app.add_typer(plan_app, name="plan")
console = Console()


class AppState:
    def __init__(self) -> None:
        self.mode = "offline"
        self.provider = "openai"
        self.model: str | None = None
        self.temperature = 0.2
        self.max_tokens = 1200


def _planner(state: AppState) -> Planner:
    cfg = PlannerConfig(
        mode=state.mode,
        provider=state.provider,
        model=state.model,
        temperature=state.temperature,
        max_tokens=state.max_tokens,
    )
    return Planner(cfg)


def _extract_mount_request(text: str) -> tuple[str, str, str] | None:
    device_match = re.search(r"(/dev/[a-zA-Z0-9._/-]+)", text)
    mountpoint_match = re.search(r"(\s|^)(/[a-zA-Z0-9._/-]+)", text)
    fstype = "xfs" if "xfs" in text.lower() else "ext4"

    if not device_match:
        return None
    device = device_match.group(1)

    mountpoint = "/data"
    if mountpoint_match:
        candidate = mountpoint_match.group(2)
        if candidate.startswith("/dev/"):
            # Find a non-device path if present.
            paths = re.findall(r"(/[^\s]+)", text)
            for p in paths:
                if not p.startswith("/dev/"):
                    mountpoint = p
                    break
        else:
            mountpoint = candidate

    mp_explicit = re.search(r"mount(?:point)?\s+(?:at\s+)?(/[^\s]+)", text.lower())
    if mp_explicit:
        mountpoint = mp_explicit.group(1)

    return device, mountpoint, fstype


def _execute_plan_interactive(plan: Plan, execute: bool, dry_run: bool) -> None:
    console.print(plan_to_markdown(plan))
    if not execute:
        console.print("[yellow]Plan generated only. Re-run with --execute to apply.[/yellow]")
        return

    confirm_text: str | None = None
    if plan.requires_confirmation_string:
        confirm_text = typer.prompt("Type exact confirmation string to proceed")

    executor = Executor(dry_run=dry_run, allow_writes=execute)
    try:
        results = executor.execute_plan(plan, confirmation_text=confirm_text)
    except Exception as exc:
        console.print(f"[red]Execution blocked/failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    executed = sum(1 for r in results if r.executed)
    console.print(f"Completed {len(results)} commands ({executed} executed). Log: {executor.log_file}")


@app.callback()
def main(
    ctx: typer.Context,
    mode: Annotated[str, typer.Option("--mode", help="offline or ai")] = "offline",
    provider: Annotated[str, typer.Option("--provider", help="openai or anthropic")] = "openai",
    model: Annotated[str | None, typer.Option("--model", help="Provider-specific model name")] = None,
    temperature: Annotated[float, typer.Option("--temperature")] = 0.2,
    max_tokens: Annotated[int, typer.Option("--max-tokens")] = 1200,
) -> None:
    if mode not in {"offline", "ai"}:
        raise typer.BadParameter("--mode must be offline or ai")
    if provider not in {"openai", "anthropic"}:
        raise typer.BadParameter("--provider must be openai or anthropic")
    state = AppState()
    state.mode = mode
    state.provider = provider
    state.model = model
    state.temperature = temperature
    state.max_tokens = max_tokens
    ctx.obj = state


@app.command()
def scan(ctx: typer.Context, output: Annotated[str, typer.Option("--output", help="text|json")] = "text") -> None:
    """Collect block and mount context."""
    planner = _planner(ctx.obj)
    data = planner.build_context()
    if output == "json":
        console.print_json(to_json(data))
    else:
        console.print(Panel.fit(data["block"].get("lsblk", "no lsblk output"), title="lsblk"))
        console.print(Panel.fit(data["block"].get("df", "no df output"), title="df -hT"))


@app.command()
def space(
    ctx: typer.Context,
    path: str,
    top_n: Annotated[int, typer.Option("--top-n")] = 10,
    output: Annotated[str, typer.Option("--output", help="text|json")] = "text",
) -> None:
    """Analyze disk usage under a path (single filesystem by default)."""
    planner = _planner(ctx.obj)
    c = planner.build_context(target_path=path, top_n=top_n)
    space_obj = c["space_analysis_obj"]
    if output == "json":
        console.print_json(to_json(space_obj))
    else:
        console.print(space_to_markdown(space_obj))


@app.command()
def advise(
    ctx: typer.Context,
    path: Annotated[str, typer.Option("--path", help="target path for analysis")] = "/",
    output: Annotated[str, typer.Option("--output", help="text|json")] = "text",
) -> None:
    """Generate cleanup advice from offline rules or AI with fallback."""
    planner = _planner(ctx.obj)
    context = planner.build_context(target_path=path)
    advice, warnings = planner.advise(context)
    for w in warnings:
        console.print(f"[yellow]warning:[/yellow] {w}")

    if output == "json":
        console.print_json(to_json(advice))
    else:
        console.print(advice_to_markdown(advice))


@app.command()
def chat(
    ctx: typer.Context,
    request: Annotated[str, typer.Argument(help="Natural-language request")],
    execute: Annotated[bool, typer.Option("--execute", help="Allow write execution for matched mount requests")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run", help="Print only; no execution")] = True,
) -> None:
    """Chat-style command that maps natural language to safe storai actions."""
    planner = _planner(ctx.obj)
    req_l = request.lower()

    if any(k in req_l for k in ["scan", "disks", "lsblk", "show storage"]):
        data = planner.build_context()
        console.print(Panel.fit(data["block"].get("lsblk", "no lsblk output"), title="lsblk"))
        console.print(Panel.fit(data["block"].get("df", "no df output"), title="df -hT"))
        return

    if any(k in req_l for k in ["space", "usage", "largest", "big files", "big directories"]):
        path = "/"
        m = re.search(r"\s(/[^\s]+)", request)
        if m:
            path = m.group(1)
        c = planner.build_context(target_path=path)
        console.print(space_to_markdown(c["space_analysis_obj"]))
        return

    if any(k in req_l for k in ["advise", "cleanup", "clean up", "free space", "recommend"]):
        path = "/"
        m = re.search(r"\s(/[^\s]+)", request)
        if m:
            path = m.group(1)
        context = planner.build_context(target_path=path)
        advice, warnings = planner.advise(context)
        for w in warnings:
            console.print(f"[yellow]warning:[/yellow] {w}")
        console.print(advice_to_markdown(advice))
        return

    if any(k in req_l for k in ["mount", "format", "filesystem", "file system"]):
        parsed = _extract_mount_request(request)
        if not parsed:
            console.print(
                "[red]Could not parse mount request.[/red] Include at least a device path like /dev/sdc and mountpoint like /data."
            )
            raise typer.Exit(code=2)
        device, mountpoint, fstype = parsed
        plan = planner.plan_mount(device=device, mountpoint=mountpoint, fstype=fstype)
        _execute_plan_interactive(plan, execute=execute, dry_run=dry_run)
        return

    console.print("I can help with: scan, space analysis, cleanup advice, and mount plan/apply requests.")
    console.print("Example: storai chat \"format /dev/sdc as ext4 and mount at /data\" --execute --no-dry-run")


@plan_app.command("mount")
def plan_mount(
    ctx: typer.Context,
    device: Annotated[str, typer.Option("--device")],
    mountpoint: Annotated[str, typer.Option("--mountpoint")],
    fstype: Annotated[str, typer.Option("--fstype")] = "ext4",
    out: Annotated[Path | None, typer.Option("--out", help="Write plan JSON file")] = None,
    output: Annotated[str, typer.Option("--output", help="text|json")] = "text",
) -> None:
    """Build a safe mount plan. Does not execute changes."""
    planner = _planner(ctx.obj)
    plan = planner.plan_mount(device=device, mountpoint=mountpoint, fstype=fstype)
    if out:
        out.write_text(json.dumps(plan.model_dump(mode="json"), indent=2), encoding="utf-8")
    if output == "json":
        console.print_json(to_json(plan))
    else:
        console.print(plan_to_markdown(plan))


@app.command()
def apply(
    planfile: Path,
    execute: Annotated[bool, typer.Option("--execute", help="Actually execute write commands")] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run/--no-dry-run", help="Print only; no execution"),
    ] = True,
) -> None:
    """Apply a saved plan with strict confirmation checks."""
    if not planfile.exists():
        raise typer.BadParameter(f"Plan file not found: {planfile}")

    payload = json.loads(planfile.read_text(encoding="utf-8"))
    plan = Plan.model_validate(payload)

    _execute_plan_interactive(plan, execute=execute, dry_run=dry_run)


if __name__ == "__main__":
    app()
