"""Typed local chat orchestration without action execution or remote fallback."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from uuid import UUID, uuid4

from pydantic import ValidationError

from aether.context.assembler import ContextAssembler, ContextOverflow, ConversationMessage
from aether.core.contracts.chat import ChatTurnRequest
from aether.core.contracts.decision import Decision, DecisionKind
from aether.core.contracts.task import TaskState
from aether.core.contracts.tool import ToolRequest
from aether.core.policy.broker import PolicyBroker
from aether.core.tasks.state_machine import TaskCapacityError, TaskStore
from aether.core.tools.mock_registry import (
    InvalidCapabilityArguments,
    MockToolRegistry,
    UnknownCapability,
)
from aether.model_gateway.base import (
    ModelGateway,
    ModelGatewayError,
    ModelMalformedResponse,
    ModelTimeout,
    ModelUnavailable,
)


@dataclass(frozen=True, slots=True)
class ChatFailure(Exception):
    status_code: int
    code: str
    message: str
    task_id: UUID
    correlation_id: UUID
    repair_attempted: bool = False


@dataclass(frozen=True, slots=True)
class ChatOutcome:
    task_id: UUID
    correlation_id: UUID
    conversation_id: UUID
    decision: Decision
    task_state: TaskState
    model_id: str | None
    context_truncated: bool
    generation_metrics: dict[str, int | float | None]
    repair_attempted: bool
    policy_status: str


class ChatTurnService:
    """Coordinates local model turns; tool proposals are validated, never invoked."""

    def __init__(
        self,
        gateway: ModelGateway,
        *,
        tasks: TaskStore | None = None,
        context: ContextAssembler | None = None,
        mock_tools: MockToolRegistry | None = None,
        max_conversations: int = 128,
        max_history_turns: int = 8,
    ) -> None:
        self.gateway = gateway
        self.tasks = tasks or TaskStore()
        self.context = context or ContextAssembler(history_turn_limit=max_history_turns // 2)
        self.mock_tools = mock_tools or MockToolRegistry()
        self.policy_broker = PolicyBroker()
        self.max_conversations = max_conversations
        self.max_history_turns = max_history_turns
        self._history: dict[UUID, list[ConversationMessage]] = {}
        self._last_used: list[UUID] = []
        self._generation_gate = asyncio.Semaphore(1)
        self._last_repair_attempted = False

    async def turn(self, request: ChatTurnRequest) -> ChatOutcome:
        correlation_id = uuid4()
        try:
            task = self.tasks.create("Local text chat turn")
        except TaskCapacityError as exc:
            raise ChatFailure(
                503,
                "TASK_CAPACITY_REACHED",
                "The in-memory task store is temporarily full; retry after proposals expire.",
                uuid4(),
                correlation_id,
            ) from exc
        task_id = UUID(task.task_id)
        conversation_id = request.conversation_id or uuid4()
        self.tasks.transition(task_id, TaskState.PLANNING)
        if self._generation_gate.locked():
            raise self._fail(
                task_id,
                correlation_id,
                429,
                "GENERATION_BUSY",
                "A local generation is already active; retry shortly.",
                repair_attempted=False,
            )
        async with self._generation_gate:
            self._last_repair_attempted = False
            try:
                health = await self.gateway.health()
                if not health.ready:
                    raise ModelUnavailable("verified local model is not ready")
                history = list(self._history.get(conversation_id, []))
                capability_catalog = json.dumps(
                    self.mock_tools.capability_schemas(), sort_keys=True, separators=(",", ":")
                )
                output_contract = (
                    "Output JSON conforming exactly to the provided Decision schema. "
                    "Never claim a tool ran; a request_tool is only a proposal. "
                    "Registered mock-only proposal IDs and schemas: "
                    f"{capability_catalog}"
                )
                assembled = await self.context.assemble(
                    user_text=request.message,
                    history=history,
                    token_counter=self.gateway,
                    output_contract=output_contract,
                )
                decision = await self._validated_decision(
                    assembled.messages, request.max_output_tokens
                )
                policy_status = "not_applicable"
                if decision.kind == DecisionKind.REQUEST_TOOL:
                    proposal = decision.tool_proposal
                    assert proposal is not None
                    self.mock_tools.validate(proposal.capability_id, proposal.arguments)
                    policy_decision = self.policy_broker.evaluate(
                        ToolRequest(
                            request_id=str(uuid4()),
                            task_id=str(task_id),
                            capability_id=proposal.capability_id,
                            arguments=proposal.arguments,
                            reason=proposal.rationale,
                            expected_effect="proposal only; no execution",
                        )
                    )
                    if policy_decision.allowed:
                        raise RuntimeError("Phase 1 policy unexpectedly allowed a capability")
                    policy_status = "denied_by_default"
                    self.tasks.transition(task_id, TaskState.AWAITING_APPROVAL)
                elif decision.kind in {DecisionKind.PROPOSE_PLAN, DecisionKind.OFFER_RSI}:
                    # Phase 1 records discussion proposals as completed text turns;
                    # neither kind opens an approval flow or performs an action.
                    self.tasks.transition(task_id, TaskState.COMPLETED)
                else:
                    self.tasks.transition(task_id, TaskState.COMPLETED)
                self._remember(
                    conversation_id, request.message, decision.text or decision.proposal or ""
                )
                return ChatOutcome(
                    task_id=task_id,
                    correlation_id=correlation_id,
                    conversation_id=conversation_id,
                    decision=decision,
                    task_state=self.tasks.get(task_id).state,  # type: ignore[union-attr]
                    model_id=health.model_id,
                    context_truncated=assembled.truncated,
                    generation_metrics=getattr(self.gateway, "last_generation_metrics", {}),
                    repair_attempted=self._last_repair_attempted,
                    policy_status=policy_status,
                )
            except ChatFailure:
                raise
            except ContextOverflow as exc:
                raise self._fail(
                    task_id, correlation_id, 413, "CONTEXT_OVERFLOW", str(exc)
                ) from exc
            except (UnknownCapability, InvalidCapabilityArguments) as exc:
                raise self._fail(
                    task_id,
                    correlation_id,
                    502,
                    "INVALID_TOOL_PROPOSAL",
                    "Model response contained an unknown or invalid mock capability proposal.",
                ) from exc
            except ModelTimeout as exc:
                raise self._fail(
                    task_id, correlation_id, 504, "MODEL_TIMEOUT", "Local model timed out."
                ) from exc
            except ModelMalformedResponse as exc:
                raise self._fail(
                    task_id,
                    correlation_id,
                    502,
                    "MODEL_OUTPUT_INVALID",
                    "Local model output could not be validated.",
                ) from exc
            except ModelGatewayError as exc:
                raise self._fail(
                    task_id,
                    correlation_id,
                    503,
                    exc.code.upper(),
                    "Local model is unavailable or rejected the request.",
                ) from exc
            except Exception as exc:
                raise self._fail(
                    task_id,
                    correlation_id,
                    500,
                    "CHAT_TURN_FAILED",
                    "The local chat turn failed safely.",
                ) from exc

    async def _validated_decision(
        self, messages: list[dict[str, str]], max_tokens: int
    ) -> Decision:
        schema = Decision.model_json_schema()
        try:
            raw = await self.gateway.generate_structured(
                messages, schema=schema, max_tokens=max_tokens
            )
            return self._parse_and_validate(raw)
        except (
            ModelGatewayError,
            ValidationError,
            ValueError,
            TypeError,
            json.JSONDecodeError,
        ) as first_error:
            if isinstance(first_error, ModelGatewayError) and not isinstance(
                first_error, ModelMalformedResponse
            ):
                raise
            # Exactly one bounded local repair. Raw malformed output is not copied
            # back into the prompt or logs; the repair contains only an error code.
            self._last_repair_attempted = True
            repair_messages = [
                *messages,
                {
                    "role": "user",
                    "content": "The prior response failed JSON/schema validation. Return a fresh valid Decision JSON object only. The invalid content is omitted.",
                },
            ]
            try:
                repaired = await self.gateway.generate_structured(
                    repair_messages, schema=schema, max_tokens=max_tokens
                )
                return self._parse_and_validate(repaired)
            except (
                ModelGatewayError,
                ValidationError,
                ValueError,
                TypeError,
                json.JSONDecodeError,
            ) as second_error:
                if isinstance(second_error, ModelGatewayError) and not isinstance(
                    second_error, ModelMalformedResponse
                ):
                    raise
                raise ModelMalformedResponse(
                    "decision schema validation failed after one repair"
                ) from second_error

    def _parse_and_validate(self, raw: str) -> Decision:
        try:
            value = json.loads(raw)
            decision = Decision.model_validate(value)
            if decision.kind == DecisionKind.REQUEST_TOOL:
                proposal = decision.tool_proposal
                assert proposal is not None
                self.mock_tools.validate(proposal.capability_id, proposal.arguments)
            return decision
        except (
            json.JSONDecodeError,
            ValidationError,
            UnknownCapability,
            InvalidCapabilityArguments,
        ) as exc:
            raise ModelMalformedResponse("decision failed semantic or schema validation") from exc

    def _fail(
        self,
        task_id: UUID,
        correlation_id: UUID,
        status_code: int,
        code: str,
        message: str,
        *,
        repair_attempted: bool | None = None,
    ) -> ChatFailure:
        record = self.tasks.get(task_id)
        if record is not None and record.state not in {
            TaskState.COMPLETED,
            TaskState.FAILED,
            TaskState.CANCELLED,
        }:
            self.tasks.transition(task_id, TaskState.FAILED, error_code=code)
        return ChatFailure(
            status_code,
            code,
            message,
            task_id,
            correlation_id,
            self._last_repair_attempted if repair_attempted is None else repair_attempted,
        )

    def _remember(self, conversation_id: UUID, user_text: str, answer: str) -> None:
        self._history.setdefault(conversation_id, []).extend(
            [ConversationMessage("user", user_text), ConversationMessage("assistant", answer)]
        )
        self._history[conversation_id] = self._history[conversation_id][-self.max_history_turns :]
        if conversation_id in self._last_used:
            self._last_used.remove(conversation_id)
        self._last_used.append(conversation_id)
        while len(self._last_used) > self.max_conversations:
            oldest = self._last_used.pop(0)
            self._history.pop(oldest, None)
