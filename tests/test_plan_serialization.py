import json

from storai.models import CommandSpec, Plan, PlanStep, RiskLevel


class FakeExecutor:
    def __init__(self) -> None:
        self.ran: list[str] = []

    def run(self, plan: Plan) -> None:
        for step in plan.steps:
            for cmd in step.commands:
                self.ran.append(cmd.to_shell())


def test_plan_round_trip_and_fake_executor() -> None:
    plan = Plan(
        goal="test",
        steps=[
            PlanStep(
                id="s1",
                title="demo",
                rationale="demo",
                risk=RiskLevel.LOW,
                commands=[CommandSpec(command="lsblk", args=["-J"])],
            )
        ],
    )

    payload = json.dumps(plan.model_dump(mode="json"))
    rebuilt = Plan.model_validate(json.loads(payload))
    assert rebuilt.goal == "test"

    fake = FakeExecutor()
    fake.run(rebuilt)
    assert fake.ran == ["lsblk -J"]
