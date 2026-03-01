from storai.llm_client import LLMClient, LLMOutputError
from storai.planner import Planner, PlannerConfig


class BrokenClient(LLMClient):
    def generate_advice(self, context: dict):
        raise LLMOutputError("invalid json")

    def generate_plan(self, context: dict, goal: str):
        raise LLMOutputError("invalid json")

    def explain_findings(self, context: dict) -> str:
        return "broken"


class SpaceObj:
    def __init__(self) -> None:
        self.top_dirs = []
        self.top_files = []
        self.inode_report = ""

    def model_dump(self):
        return {"top_dirs": [], "top_files": [], "inode_report": ""}


def test_ai_parse_failure_falls_back_to_offline() -> None:
    planner = Planner(PlannerConfig(mode="offline"))
    planner.config.mode = "ai"
    planner.client = BrokenClient()

    context = {
        "space_analysis_obj": SpaceObj(),
        "space_analysis": {"top_dirs": []},
    }
    advice, warnings = planner.advise(context)
    assert advice.source == "offline"
    assert warnings
    assert "fallback" in warnings[0].lower()
