"""Offline verifier for IAGA Sentinel signed receipt chains, in pure Python.

This is the Python half of the multilingual verifier (roadmap 1.3 "verifier
sovereignty"): an auditor on a Python stack reaches the *same verdict* as the
canonical Rust `iaga-verify`, from the same exported chain, with **no
third-party dependencies** — only the standard library. Run it on an
air-gapped laptop:

    python iaga_verify.py chain.json --key <hex-ed25519-pubkey>

Exit codes match the Rust binary: 0 chain valid, 1 chain broken or empty,
2 usage error, 3 IO/parse/unsupported error.

How the signed bytes are recovered
----------------------------------
A receipt is signed over ``serde_json::to_vec(&ReceiptBody)`` — compact JSON,
no spaces, in struct *declaration* order, with optional/empty fields elided.
The export already stores each body's fields in that exact order (serde emits
them so, and JSON parsers preserve key order), so the signed bytes are simply
the receipt object minus its ``signature`` key, re-dumped compactly. For the
float-free values every OSS receipt carries (strings, ints, bools, null,
arrays, objects), ``json.dumps(separators=(",",":"), ensure_ascii=False)`` is
byte-identical to serde_json. A receipt carrying floating-point values (e.g.
``ml_scores``) is *refused* (exit 3) rather than verified with possibly
divergent bytes — honesty over a guessed verdict.

Parity is not assumed: ``tests/test_iaga_verify.py`` checks this verifier
against ``sdks/conformance/golden_chain.json``, a chain signed by the canonical
Rust code, plus an RFC 8032 known-answer vector for the Ed25519 primitive.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from typing import Any, Optional

# --------------------------------------------------------------------------
# Vendored Ed25519 verification (RFC 8032), pure standard library.
#
# Public-domain reference arithmetic (Bernstein et al.), verify-only: it takes
# a public key, never a secret, so it has no side-channel exposure relevant to
# a verifier. Validated by an RFC 8032 known-answer test in the test suite.
# --------------------------------------------------------------------------

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _Q - 2, _Q)


_D = (-121665 * _inv(121666)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * _inv(5)) % _Q
_BX = _xrecover(_BY)
_B = (_BX % _Q, _BY % _Q)


def _edwards_add(p: tuple, q: tuple) -> tuple:
    x1, y1 = p
    x2, y2 = q
    denom = _inv(1 + _D * x1 * x2 * y1 * y2)
    x3 = (x1 * y2 + x2 * y1) * denom
    denom2 = _inv(1 - _D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * denom2
    return (x3 % _Q, y3 % _Q)


def _scalarmult(p: tuple, e: int) -> tuple:
    # Iterative double-and-add (LSB first); identity is (0, 1).
    result = (0, 1)
    base = p
    while e > 0:
        if e & 1:
            result = _edwards_add(result, base)
        base = _edwards_add(base, base)
        e >>= 1
    return result


def _is_on_curve(p: tuple) -> bool:
    x, y = p
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _Q == 0


def _decodepoint(s: bytes) -> tuple:
    n = int.from_bytes(s, "little")
    y = n & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != ((n >> 255) & 1):
        x = _Q - x
    p = (x % _Q, y % _Q)
    if not _is_on_curve(p):
        raise ValueError("point not on curve")
    return p


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Return True iff ``signature`` is a valid Ed25519 signature of
    ``message`` under ``public_key``. Cofactorless check, matching the default
    ``ed25519_dalek::VerifyingKey::verify`` used by the canonical verifier."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        r = _decodepoint(signature[:32])
        a = _decodepoint(public_key)
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little")
    lhs = _scalarmult(_B, s)
    rhs = _edwards_add(r, _scalarmult(a, h))
    return lhs == rhs


# --------------------------------------------------------------------------
# Chain verification
# --------------------------------------------------------------------------


class Unsupported(Exception):
    """A receipt shape this dependency-free verifier cannot canonicalize
    byte-identically (e.g. floating-point ``ml_scores``)."""


@dataclass
class VerifyResult:
    ok: bool
    run_id: str
    receipt_count: int
    signer_key_id: str
    key_source: str  # "pinned" | "embedded"
    reason: Optional[str] = None
    broken_seq: Optional[int] = None  # None on an empty chain
    empty: bool = False


def _key_id(public_key: bytes) -> str:
    # ed25519-<first 16 bytes of SHA-256(pubkey), hex>, matching
    # iaga_sentinel_receipts::key_id_for_verifying_key.
    return "ed25519-" + hashlib.sha256(public_key).digest()[:16].hex()


def _contains_float(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(_contains_float(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_float(v) for v in value)
    return False


def _signing_bytes(receipt: dict) -> bytes:
    body = {k: v for k, v in receipt.items() if k != "signature"}
    if _contains_float(body):
        raise Unsupported(
            "receipt body contains floating-point values (e.g. ml_scores); "
            "verify with the canonical Rust iaga-verify"
        )
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_export(export: dict, pinned_key_hex: Optional[str] = None) -> VerifyResult:
    """Verify an exported receipt chain. With ``pinned_key_hex`` the chain is
    checked against that trusted key; otherwise it falls back to the
    self-asserted key embedded in the export."""
    if pinned_key_hex is not None:
        key_hex, source = pinned_key_hex.strip(), "pinned"
    else:
        key_hex, source = str(export["signer_verifying_key"]).strip(), "embedded"

    try:
        public_key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise ValueError(f"invalid public key: not hex: {exc}") from exc
    if len(public_key) != 32:
        raise ValueError(f"invalid public key: expected 32 bytes, got {len(public_key)}")

    key_id = _key_id(public_key)
    claimed = str(export.get("signer_key_id", ""))
    run_id = str(export.get("run_id", ""))
    receipts = export.get("receipts", [])

    def broken(seq: Optional[int], reason: str) -> VerifyResult:
        return VerifyResult(False, run_id, 0, claimed, source, reason=reason, broken_seq=seq)

    # Bind the claimed signer_key_id to the key that actually verifies, so the
    # printed signer= label is authenticated and not attacker-chosen.
    if claimed != key_id:
        return broken(
            0,
            f"signer_key_id mismatch: export claims {claimed} but the verifying key is {key_id}",
        )

    if not receipts:
        return VerifyResult(False, run_id, 0, claimed, source, reason="empty chain", empty=True)

    expected_parent: Optional[str] = None
    for i, r in enumerate(receipts):
        seq = r.get("seq")
        if str(r.get("signer_key_id", "")) != key_id:
            return broken(
                seq,
                f"receipt seq {seq} claims signer {r.get('signer_key_id')} "
                f"but the verifying key is {key_id}",
            )
        if str(r.get("run_id", "")) != run_id:
            return broken(seq, f"run_id mismatch: expected {run_id} got {r.get('run_id')}")
        if seq != i:
            return broken(seq, f"non-monotonic seq: expected {i} got {seq}")
        if r.get("parent_hash") != expected_parent:
            return broken(
                seq,
                f"parent_hash mismatch: expected {expected_parent!r} got {r.get('parent_hash')!r}",
            )
        message = _signing_bytes(r)
        try:
            sig = bytes.fromhex(str(r["signature"]))
        except (KeyError, ValueError):
            return broken(seq, "signature invalid: not hex")
        if not ed25519_verify(public_key, sig, message):
            return broken(seq, "signature invalid")
        expected_parent = hashlib.sha256(message).hexdigest()

    return VerifyResult(True, run_id, len(receipts), claimed, source)


# --------------------------------------------------------------------------
# CLI (mirrors the Rust `iaga-verify` surface and exit codes)
# --------------------------------------------------------------------------

_USAGE = "usage: iaga-verify <chain.json> [--key <hex-ed25519-pubkey>] [--expect-count <n>]"


def main(argv: list) -> int:
    path: Optional[str] = None
    key: Optional[str] = None
    expect_count: Optional[int] = None
    it = iter(argv)
    for a in it:
        if a in ("--key", "-k"):
            key = next(it, None)
            if key is None:
                print("iaga-verify: --key needs a hex public key", file=sys.stderr)
                return 2
        # The one honest defence against tail truncation offline, and it has to
        # exist here too: README.md offers this verifier as the way to check a
        # chain with no build at all, and sdks/conformance/README.md promises all
        # three reach the same verdict with the same exit codes. Shipping the
        # flag only in the Rust binary made that promise false for exactly the
        # reader who cannot build Rust. Wording copied from the Rust verifier.
        elif a == "--expect-count":
            raw = next(it, None)
            if raw is None:
                print("iaga-verify: --expect-count needs a value", file=sys.stderr)
                return 2
            try:
                expect_count = int(raw)
                if expect_count < 0:
                    raise ValueError
            except ValueError:
                print(
                    "iaga-verify: --expect-count needs a non-negative integer",
                    file=sys.stderr,
                )
                return 2
        elif a in ("-h", "--help"):
            print(_USAGE)
            print("Verifies the Ed25519 signatures and hash-chain links of a signed receipt chain.")
            return 0
        elif path is None:
            path = a
        else:
            print(f"iaga-verify: unexpected argument: {a}", file=sys.stderr)
            print(_USAGE, file=sys.stderr)
            return 2

    if path is None:
        print(_USAGE, file=sys.stderr)
        return 2

    try:
        with open(path, "r", encoding="utf-8") as fh:
            export = json.load(fh)
    except OSError as exc:
        print(f"iaga-verify: cannot read {path}: {exc}", file=sys.stderr)
        return 3
    except json.JSONDecodeError as exc:
        print(f"iaga-verify: {path} is not a valid chain export: {exc}", file=sys.stderr)
        return 3

    try:
        res = verify_export(export, key)
    except Unsupported as exc:
        print(f"iaga-verify: {exc}", file=sys.stderr)
        return 3
    except (ValueError, KeyError, TypeError) as exc:
        print(f"iaga-verify: verification error: {exc}", file=sys.stderr)
        return 3

    if res.key_source == "embedded":
        print(
            "warning: verifying against the key embedded in the export (self-asserted). "
            "Pass --key with the expected public key to authenticate authorship.",
            file=sys.stderr,
        )

    if res.ok:
        if expect_count is not None and res.receipt_count != expect_count:
            print(
                f"CHAIN LENGTH MISMATCH  run_id={res.run_id}  receipts={res.receipt_count}  "
                f"expected={expect_count}  signer={res.signer_key_id}  key={res.key_source}",
                file=sys.stderr,
            )
            print(
                "the chain is internally valid but not the length you anchored: "
                f"{res.receipt_count} of {expect_count} receipts. A shorter valid chain is "
                "what tail truncation looks like.",
                file=sys.stderr,
            )
            return 1
        last = max(res.receipt_count - 1, 0)
        print(
            f"CHAIN OK  run_id={res.run_id}  receipts={res.receipt_count}  "
            f"seq=0..{last}  signer={res.signer_key_id}  key={res.key_source}"
        )
        return 0
    if res.empty:
        print(f"CHAIN EMPTY  run_id={res.run_id}", file=sys.stderr)
        return 1
    print(
        f"CHAIN BROKEN  run_id={res.run_id}  seq={res.broken_seq}  reason={res.reason}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
