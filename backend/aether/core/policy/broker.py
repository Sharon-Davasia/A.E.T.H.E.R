"""Deterministic policy broker with deny-by-default Phase 1 behavior."""

from __future__ import annotations

from datetime import UTC, datetime

from aether.core.contracts.policy import PolicyDecision, RiskTier
from aether.core.contracts.tool import ToolRequest
from aether.core.grants.authority import GrantAuthority, GrantRequest
from aether.core.policy.capabilities import CapabilityRegistry, CapabilityRegistryError
from aether.core.resources.registry import ResourceRegistry, ResourceRegistryError

PHASE0_REASON_CODE = "PHASE0_DENY_ALL_OS_ACTIONS"
PHASE0_REASON = (
    "No Phase 2 registries are configured; all real OS actions remain denied by default."
)


class PolicyBroker:
    """Resolve exact registered scopes; never execute or issue approvals.

    The no-argument configuration preserves Phase 0/1 deny-all behavior. A
    configured Phase 2 broker can assess T0/T1 policy, but Phase 2A registers
    filesystem contracts as non-executable. T2 remains denied until a trusted
    approval issuer and execution adapter exist; T3 is never enabled by this
    broker. A valid Stage 4 exact grant is *scope-verified* by the optional
    ``grant_authority`` — it is never execution authorization, and grant
    consumption happens only at execution time (which does not exist yet).
    """

    def __init__(
        self,
        *,
        capabilities: CapabilityRegistry | None = None,
        resources: ResourceRegistry | None = None,
        grant_authority: GrantAuthority | None = None,
        executors: frozenset[str] = frozenset(),
        app_authority: object | None = None,
    ) -> None:
        self._capabilities = capabilities
        self._resources = resources
        self._grant_authority = grant_authority
        # Phase 3 app/window authority (AppWindowResourceAuthority).
        # Dispatch is by the *registered capability's* declared kind,
        # never by caller claims; filesystem kinds keep the existing
        # ResourceRegistry path unchanged.
        self._app_authority = app_authority
        # Capability ids for which a real, bounded execution adapter is wired in
        # *this process*. Declaring one is an explicit integration act: the
        # default is empty, so a broker built without this argument authorizes
        # nothing and every capability answers NOT_AVAILABLE.
        self._executors = executors

    def evaluate(
        self,
        request: ToolRequest,
        *,
        grant: GrantRequest | None = None,
        now: datetime | None = None,
    ) -> PolicyDecision:
        """Return deterministic authorization status, without running a capability."""
        if self._capabilities is None and self._resources is None:
            return self._deny(RiskTier.CRITICAL, PHASE0_REASON_CODE, PHASE0_REASON, True)
        if self._capabilities is None or self._resources is None:
            return self._deny(
                RiskTier.CRITICAL,
                "PHASE2_POLICY_NOT_CONFIGURED",
                "Both capability and resource registries are required.",
                True,
            )
        try:
            definition = self._capabilities.get(request.capability_id)
            arguments = self._capabilities.validate(request.capability_id, request.arguments)
        except CapabilityRegistryError as exc:
            return self._deny(
                RiskTier.CRITICAL,
                exc.reason_code,
                "Capability is not registered or its typed arguments are invalid.",
                True,
            )

        if definition.resource_kind is not None:
            if len(request.resources) != 1:
                return self._deny(
                    definition.risk_tier,
                    "RESOURCE_SCOPE_REQUIRED",
                    "Exactly one registry-issued resource reference is required.",
                    definition.risk_tier >= RiskTier.MODIFY,
                )
            resource_ref = request.resources[0]
            argument_resource_id = getattr(arguments, "resource_id", None)
            if argument_resource_id != resource_ref.resource_id:
                return self._deny(
                    definition.risk_tier,
                    "RESOURCE_ARGUMENT_MISMATCH",
                    "Typed resource argument must match the registry-issued resource reference.",
                    definition.risk_tier >= RiskTier.MODIFY,
                )
            if definition.resource_kind in ("app", "window"):
                # App/window dispatch via the Phase 3 authority only.
                from aether.core.resources.app_window_authority import (
                    AppWindowAuthorityError,
                )

                if self._app_authority is None:
                    return self._deny(
                        definition.risk_tier,
                        "APP_RESOURCE_AUTHORITY_NOT_CONFIGURED",
                        "No app/window resource authority is configured.",
                        definition.risk_tier >= RiskTier.MODIFY,
                    )
                try:
                    self._app_authority.authorize_ref(  # type: ignore[attr-defined]
                        resource_ref, expected_kind=definition.resource_kind
                    )
                except AppWindowAuthorityError as exc:
                    return self._deny(
                        definition.risk_tier,
                        exc.reason_code.upper(),
                        "App/window resource is forged, stale or out of scope.",
                        definition.risk_tier >= RiskTier.MODIFY,
                    )
                # Skip the filesystem registry check entirely.
                authorized_via_app_authority = True
                return self._after_resource_check(
                    definition, request, grant, now, authorized_via_app_authority
                )
            try:
                self._resources.authorize_ref(
                    resource_ref,
                    definition.capability_id,
                    expected_kind=definition.resource_kind,
                    max_data_class=definition.max_data_class,
                )
            except ResourceRegistryError as exc:
                return self._deny(
                    definition.risk_tier,
                    exc.reason_code.upper(),
                    "Resource is stale, protected, outside the registered root, or out of scope.",
                    definition.risk_tier >= RiskTier.MODIFY,
                )
        elif request.resources:
            return self._deny(
                definition.risk_tier,
                "UNEXPECTED_RESOURCE_SCOPE",
                "This capability does not accept resources.",
                definition.risk_tier >= RiskTier.MODIFY,
            )

        return self._after_resource_check(definition, request, grant, now, False)

    def _after_resource_check(
        self,
        definition: object,
        request: ToolRequest,
        grant: GrantRequest | None,
        now: datetime | None,
        _via_app_authority: bool,
    ) -> PolicyDecision:
        """Post-resource-check policy tail (shared fs/app dispatch)."""
        from aether.core.policy.capabilities import CapabilityDefinition

        assert isinstance(definition, CapabilityDefinition)
        if definition.risk_tier == RiskTier.CRITICAL:
            return self._deny(
                RiskTier.CRITICAL,
                "TIER3_DISABLED",
                "T3 operations are disabled in Phase 2A.",
                True,
            )
        if definition.risk_tier == RiskTier.MODIFY:
            if grant is None or self._grant_authority is None:
                return self._deny(
                    RiskTier.MODIFY,
                    "TRUSTED_APPROVAL_NOT_AVAILABLE",
                    "T2 mutation remains disabled until the trusted approval channel is implemented.",
                    True,
                )
            check = self._grant_authority.check_action(
                request,
                grant,
                risk_tier=definition.risk_tier,
                now=now or datetime.now(UTC),
            )
            if not check.ok:
                return self._deny(
                    RiskTier.MODIFY,
                    check.reason_code,
                    "T2 mutation remains denied: the exact grant failed closed validation.",
                    True,
                )
            return PolicyDecision(
                allowed=False,
                risk_tier=RiskTier.MODIFY,
                reason_code="GRANT_VALIDATED_EXECUTOR_NOT_ENABLED",
                reason=(
                    "The exact grant scope was verified against the persisted ledger, "
                    "but no execution adapter is enabled in this phase; no action was "
                    "authorized or performed."
                ),
                requires_approval=False,
                approval_id=str(grant.approval_id),
            )
        if definition.capability_id not in self._executors:
            return self._deny(
                definition.risk_tier,
                "CAPABILITY_EXECUTOR_NOT_AVAILABLE",
                "The capability contract is registered but no execution adapter is enabled.",
                False,
            )
        return PolicyDecision(
            allowed=True,
            risk_tier=definition.risk_tier,
            reason_code="CAPABILITY_AUTHORIZED",
            reason=(
                "A bounded read/navigation-tier execution adapter is enabled for "
                "this capability and the resource scope was verified."
            ),
            requires_approval=False,
            approval_id=None,
        )

    def evaluate_rsi_send(self) -> PolicyDecision:
        """RSI remains disabled; no Phase 2 policy can authorize remote sends."""
        return self._deny(
            RiskTier.CRITICAL,
            "PHASE0_RSI_DISABLED",
            "RSI is disabled. No remote sends are permitted.",
            True,
        )

    @staticmethod
    def _deny(
        tier: RiskTier, reason_code: str, reason: str, requires_approval: bool
    ) -> PolicyDecision:
        return PolicyDecision(
            allowed=False,
            risk_tier=tier,
            reason_code=reason_code,
            reason=reason,
            requires_approval=requires_approval,
            approval_id=None,
        )
