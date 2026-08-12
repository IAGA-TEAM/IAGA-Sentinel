"""`GovernanceResult.from_dict` — pure, no server needed.

Guards the `layerRoles` plumbing (S4): a consumer must be able to tell which
layers are advisory rather than deciding, or it will sum a sandbox result and a
behavioural fingerprint in with the signed verdict and overstate its coverage.
"""

from __future__ import annotations

from iaga_sentinel.types import GovernanceResult


def _base_response() -> dict:
    return {
        "traceId": "t-1",
        "decision": "allow",
        "reviewStatus": "not_required",
        "risk": {"score": 2, "decision": "allow", "reasons": []},
        "policyFindings": [],
        "protocol": "http-function",
    }


def test_layer_roles_are_parsed_when_present() -> None:
    data = _base_response()
    data["layerRoles"] = {
        "taintAnalysis": {"role": "veto"},
        "sandboxResult": {"role": "advisory", "note": "containment only"},
        "adaptiveRisk": {"role": "scoring"},
    }
    result = GovernanceResult.from_dict(data)

    assert result.layer_roles["taintAnalysis"]["role"] == "veto"
    assert result.is_advisory_layer("sandboxResult") is True
    assert result.is_advisory_layer("taintAnalysis") is False
    assert result.is_advisory_layer("adaptiveRisk") is False


def test_missing_layer_roles_do_not_reclassify_anything() -> None:
    # An older server sends no layerRoles. The safe default is "not advisory":
    # calling every layer advisory would be as misleading as calling none.
    result = GovernanceResult.from_dict(_base_response())

    assert result.layer_roles == {}
    assert result.is_advisory_layer("sandboxResult") is False


def test_unknown_layer_is_not_advisory() -> None:
    data = _base_response()
    data["layerRoles"] = {"taintAnalysis": {"role": "veto"}}
    result = GovernanceResult.from_dict(data)

    assert result.is_advisory_layer("somethingNew") is False
