"""IAGA Sentinel SDK - zero-trust governance for autonomous AI agents."""

from .client import SentinelClient, AsyncSentinelClient
from .decorator import governed
from .types import (
    ActionDetail,
    ActionType,
    GovernanceDecision,
    GovernanceResult,
    InspectRequest,
    PluginOutput,
    PluginResult,
    ProtocolKind,
    ReviewStatus,
)

__version__ = "2.0.0"
__all__ = [
    "SentinelClient",
    "AsyncSentinelClient",
    "InspectRequest",
    "ActionDetail",
    "ActionType",
    "GovernanceResult",
    "GovernanceDecision",
    "ProtocolKind",
    "ReviewStatus",
    "PluginResult",
    "PluginOutput",
    "governed",
]
