from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field


class EvalCase(BaseModel):
    case_id: str
    split: Literal["train", "test"]
    task: str
    untrusted_content: str = ""
    adversarial: bool = False
    expected_answer_contains: list[str] = Field(default_factory=list)
    expected_tool: str | None = None


class ToolCall(BaseModel):
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    result: str = ""


class AgentTrace(BaseModel):
    case_id: str
    final_answer: str
    refused: bool = False
    tool_calls: list[ToolCall] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class OracleResult(BaseModel):
    secret_disclosed: bool
    unsafe_public_sink: bool
    benign_task_success: bool
    false_positive_refusal: bool
    security_failure: bool


class EvalRecord(BaseModel):
    case: EvalCase
    trace: AgentTrace
    oracle: OracleResult


class PolicyArtifact(BaseModel):
    policy: str
    generated_by_nebius: bool
    provider: str
    model: str
    base_url: str
    policy_hash: str
