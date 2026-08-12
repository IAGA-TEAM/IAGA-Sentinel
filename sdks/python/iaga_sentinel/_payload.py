"""Payload construction shared by the decorator and the framework adapters.

This module exists to keep the import graph acyclic in the direction that
matters. ``named_payload`` and ``_safe_value`` are generic helpers — they know
about function signatures and JSON-safe values, and nothing about any
framework — but they used to live in ``adapters/_common.py``. ``decorator.py``
importing them from there made ``import iaga_sentinel`` execute
``adapters/__init__.py``, which eagerly imports nine framework adapters, so the
cost of importing the package's simplest entry point was the entire adapter
surface.

There is no cycle today and there was none before; the defect is directional.
A leaf became dependent on the widest module in the package, which is the shape
that turns one adapter's broken third-party import into a failure of
``import iaga_sentinel`` itself.

``adapters/_common.py`` re-exports both names, so anything importing them from
there keeps working unchanged — today that is ``adapters/langchain.py`` for
``_safe_value``, plus ``_common``'s own use of ``named_payload``.
"""

from __future__ import annotations

import inspect
from typing import Any, Callable

# Argument names never sent to the sidecar. `self` is the one that had to go:
# it is an instance repr nobody chose to send, and `action.payload` is hashed
# into the signed receipt, so an object holding a credential got signed.
DEFAULT_EXCLUDE: tuple[str, ...] = ("self", "ctx", "context")


def _safe_value(val: Any) -> Any:
    """Convert a value to a JSON-safe representation."""
    if isinstance(val, (str, int, float, bool, type(None))):
        return val
    if isinstance(val, (list, tuple)):
        return [_safe_value(v) for v in val]
    if isinstance(val, dict):
        return {str(k): _safe_value(v) for k, v in val.items()}
    return str(val)


def named_payload(
    func: Callable,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    exclude: tuple[str, ...] = DEFAULT_EXCLUDE,
) -> dict[str, Any]:
    """Build a payload from a function's named arguments, skipping ``exclude``.

    Positional arguments past the end of the signature are named ``arg{i}``
    rather than dropped, so a ``*args`` call does not under-report what it did.
    """
    try:
        params = list(inspect.signature(func).parameters.keys())
    except (TypeError, ValueError):
        params = []
    payload: dict[str, Any] = {}
    for i, arg in enumerate(args):
        name = params[i] if i < len(params) else f"arg{i}"
        if name in exclude:
            continue
        payload[name] = _safe_value(arg)
    for key, value in kwargs.items():
        if key in exclude:
            continue
        payload[key] = _safe_value(value)
    return payload
