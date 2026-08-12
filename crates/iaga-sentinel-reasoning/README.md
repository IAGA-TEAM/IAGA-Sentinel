# iaga-sentinel-reasoning

Probabilistic Reasoning Plane for IAGA Sentinel (introduced in 1.0 M3.5).

ML produces **evidence**, never verdicts. The deterministic policy layer
decides; this crate just feeds it scores.

## Backends

| Backend       | Feature flag | Native deps | Use case                |
|---------------|--------------|-------------|-------------------------|
| `NoopEngine`  | always on    | none        | tests, ML disabled prod |
| `TractEngine` | `ml`         | none        | production with ONNX    |

`tract-onnx` is pure Rust. No system libraries to install, no linker
dance, builds clean on Linux / macOS / Windows. GPU acceleration and
the `ort` (ONNX Runtime native) backend ship in IAGA Sentinel
Enterprise as part of the curated ML model library, see
[`docs/adr/0010-oss-enterprise-boundary.md`](../../docs/adr/0010-oss-enterprise-boundary.md)
(see the Enterprise bullet on curated model libraries).

## Configuring models

The host (`iaga-sentinel-core`) reads model paths from the environment:

```
IAGA_SENTINEL_REASONING_MODELS=intent_drift:/path/to/a.onnx,prompt_injection:/path/to/b.onnx
```

Format: `name:path` pairs, comma-separated. Malformed entries are
silently dropped (with a `warn!` log). Empty / unset → engine falls
back to `NoopEngine` and the pipeline runs without ML evidence.

## Verifying a deployment

```
$ cargo build --release --features ml
$ iaga reasoning info
engine: tract
models: 2
  - intent_drift             sha256=8f4a3c...
  - prompt_injection         sha256=2b9e1d...
```

The SHA-256 of every loaded model is embedded in every signed receipt
the host produces (see `iaga-sentinel-receipts`). That's what makes cross-version
replay deterministic: change a model, the digest changes, replay flags
the drift cleanly.

## Tokenizer (MVP)

The MVP tokenizer is a hash bag of byte n-grams projected to a fixed
`[1, 64]` float32 vector. It is deterministic and zero-dep. It is **not**
a real linguistic tokenizer and you cannot pair it with off-the-shelf
HuggingFace models. The HuggingFace tokenizer integration + curated
calibration framework ship in IAGA Sentinel Enterprise as part of the
curated ML model library (see
[ADR 0010](../../docs/adr/0010-oss-enterprise-boundary.md), Decision →
Enterprise scope). The OSS
BYO ONNX path remains: bring any model that accepts the `[1, 64]`
float32 input, or train a small classifier on top of the same hash
features.

For day-1 deployment, train a small classifier (logistic regression,
linear SVM) on top of the same 64-dim hash features and export to ONNX.
Score quality won't beat a real LM, but the wiring is real and the
signed-receipt chain works end to end.

## Failure policy

Every implementation must respect two invariants:

1. `evaluate` never panics, never propagates errors. A broken model
   contributes empty evidence; the host pipeline keeps running.
2. `model_digests` is stable for the lifetime of the engine.

These are enforced by trait contract and reinforced by the integration
tests in `iaga-sentinel-core`.

## License

BUSL-1.1 with Change License: Apache-2.0 baked into the licence
itself (auto-converts four years after each release is published).
See [ADR 0002](../../docs/adr/0002-open-source-license-and-scope.md).
