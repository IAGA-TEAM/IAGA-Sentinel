//! Tract-based ONNX inference engine. Compiled only when the `ml`
//! feature is on so the no-feature build stays slim.
//!
//! Design:
//! - One `LoadedModel` per ONNX file. The host registers them by
//!   `(name, path)` pairs; the engine reads the file once, computes
//!   the SHA-256 digest, and keeps an optimized runnable in memory.
//! - Tokenization is deliberately primitive (hash-bag of byte n-grams)
//!   so the MVP can run any model with a `[1, N]` float32 input
//!   without dragging in HuggingFace tokenizers. Real workloads will
//!   ship a tokenizer alongside the model, wired in M3.5.1.
//! - Inference produces a single scalar score per model, taken as the
//!   first element of the output tensor. Models with richer outputs
//!   are supported in M5 when Dictum gains `ml.*` evidence paths.
//!
//! Failure policy: any per-model failure during `evaluate` is logged
//! (via `tracing` if the host wires it) and contributes nothing to
//! the evidence, never propagated as an error. A broken model must
//! not knock the pipeline offline.

#![cfg(feature = "ml")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use tract_onnx::prelude::*;

use crate::digest::sha256_hex;
use crate::engine::ReasoningEngine;
use crate::errors::{ReasoningError, Result};
use crate::evidence::{EvalInput, MlEvidence, ModelDigest};

/// Default feature vector size produced by the MVP tokenizer.
/// Models accepting `[1, INPUT_DIM]` float32 work out of the box.
pub const INPUT_DIM: usize = 64;

type RunnableModel =
    Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>;

struct LoadedModel {
    name: String,
    digest: ModelDigest,
    runner: RunnableModel,
}

pub struct TractEngine {
    models: Vec<LoadedModel>,
}

impl TractEngine {
    /// Empty engine, useful as a placeholder before models are loaded
    /// or in tests that don't need real inference.
    pub fn empty() -> Self {
        Self { models: Vec::new() }
    }

    /// Load every `(name, path)` pair into the engine. Errors short-
    /// circuit construction: a half-loaded engine would silently skip
    /// models the operator believes are active.
    pub fn from_paths<P: AsRef<Path>>(specs: &[(&str, P)]) -> Result<Self> {
        let mut models = Vec::with_capacity(specs.len());
        for (name, path) in specs {
            let path = path.as_ref();
            models.push(load_model(name, path)?);
        }
        Ok(Self { models })
    }

    /// Number of currently loaded models. Used by `iaga reasoning info`.
    pub fn model_count(&self) -> usize {
        self.models.len()
    }
}

fn load_model(name: &str, path: &Path) -> Result<LoadedModel> {
    if !path.exists() {
        return Err(ReasoningError::ModelNotFound {
            path: path.display().to_string(),
        });
    }
    let bytes = std::fs::read(path)?;
    let digest = ModelDigest {
        name: name.to_string(),
        sha256: sha256_hex(&bytes),
    };
    let mut cursor = std::io::Cursor::new(&bytes);
    let model = tract_onnx::onnx()
        .model_for_read(&mut cursor)
        .and_then(|m| m.into_optimized())
        .and_then(|m| m.into_runnable())
        .map_err(|e| ReasoningError::ModelLoad {
            name: name.to_string(),
            msg: e.to_string(),
        })?;
    Ok(LoadedModel {
        name: name.to_string(),
        digest,
        runner: Arc::new(model),
    })
}

/// FNV-1a 64-bit, vendored and versioned (DET-REASONING-1).
///
/// The previous tokenizer bucketed trigrams with `std`'s `DefaultHasher`
/// (SipHash), whose output is explicitly **not** stable across std versions or
/// targets by contract. Because the resulting feature vector feeds the signed
/// `ml_scores`, an unstable hash means two builds of the same source sign
/// different receipts (the chain hash diverges). FNV-1a with explicit
/// constants is a fixed function of the bytes, so the buckets — and the signed
/// score — are reproducible across toolchains and machines.
///
/// `v1` constants: offset basis `0xcbf29ce484222325`, prime `0x100000001b3`.
/// Changing them is a wire change (re-version + CHANGELOG).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// MVP tokenizer: hash byte n-grams (n=3) into a fixed-size float32 vector.
/// Deterministic given the same input string AND stable across toolchains
/// (FNV-1a, see [`fnv1a64`]), which is what receipt replay needs. Produces a
/// `[1, INPUT_DIM]` shape.
fn tokenize(input: &EvalInput) -> Vec<f32> {
    let mut feats = vec![0.0f32; INPUT_DIM];
    let payload = input.payload_text.as_bytes();
    if payload.len() < 3 {
        return feats;
    }
    for window in payload.windows(3) {
        let bucket = (fnv1a64(window) as usize) % INPUT_DIM;
        feats[bucket] += 1.0;
    }
    let max = feats.iter().cloned().fold(0.0f32, f32::max);
    if max > 0.0 {
        for v in feats.iter_mut() {
            *v /= max;
        }
    }
    feats
}

fn run_one(model: &LoadedModel, input_vec: &[f32]) -> Result<f32> {
    let tensor = tract_ndarray::Array2::from_shape_vec((1, input_vec.len()), input_vec.to_vec())
        .map_err(|e| ReasoningError::Inference {
            name: model.name.clone(),
            msg: e.to_string(),
        })?
        .into_tensor();
    let result = model
        .runner
        .run(tvec!(tensor.into()))
        .map_err(|e| ReasoningError::Inference {
            name: model.name.clone(),
            msg: e.to_string(),
        })?;
    let out = result
        .into_iter()
        .next()
        .ok_or_else(|| ReasoningError::Inference {
            name: model.name.clone(),
            msg: "model returned no outputs".into(),
        })?;
    let slice = out
        .as_slice::<f32>()
        .map_err(|e| ReasoningError::Inference {
            name: model.name.clone(),
            msg: e.to_string(),
        })?;
    slice
        .first()
        .copied()
        .ok_or_else(|| ReasoningError::Inference {
            name: model.name.clone(),
            msg: "model output tensor was empty".into(),
        })
}

/// Quantize an f32 model score onto a fixed `1e-6` grid (as f64) before it
/// enters the signed `ml_scores` (DET-REASONING-2).
///
/// The raw f32 ONNX output can differ by a few ULP across microarchitectures
/// (SIMD/FMA), which would change the signed bytes — and therefore the chain
/// hash — between two builds of the same model on different hardware. Rounding
/// to six decimals absorbs those sub-grid differences. This is a best-effort
/// mitigation, not a hardware-independence guarantee: a score sitting exactly on
/// a grid boundary can still tip. Pair with the versioned FNV tokenizer
/// (DET-REASONING-1) for the input side.
fn quantize_score(s: f32) -> f64 {
    (f64::from(s) * 1_000_000.0).round() / 1_000_000.0
}

#[async_trait]
impl ReasoningEngine for TractEngine {
    async fn evaluate(&self, input: &EvalInput) -> MlEvidence {
        if self.models.is_empty() {
            return MlEvidence::empty();
        }
        let feats = tokenize(input);
        let mut scores = serde_json::Map::with_capacity(self.models.len());
        let mut failed_models = Vec::new();
        for m in &self.models {
            match run_one(m, &feats) {
                Ok(s) => {
                    scores.insert(m.name.clone(), json!({ "score": quantize_score(s) }));
                }
                Err(e) => {
                    // Soft-fail: the model contributes nothing this round, but
                    // the failure is no longer silent (1.5.2) — it is logged
                    // and recorded in `failed_models` so consumers can tell a
                    // crashed model from one that scored nothing.
                    tracing::warn!(model = %m.name, error = %e, "ml inference failed; skipping model for this input");
                    failed_models.push(m.name.clone());
                }
            }
        }
        MlEvidence {
            scores: serde_json::Value::Object(scores),
            model_digests: self.models.iter().map(|m| m.digest.clone()).collect(),
            failed_models,
        }
    }

    fn model_digests(&self) -> Vec<ModelDigest> {
        self.models.iter().map(|m| m.digest.clone()).collect()
    }

    fn name(&self) -> &'static str {
        "tract"
    }
}

/// Resolve `IAGA_SENTINEL_REASONING_MODELS` from the environment. Format:
/// `name1:path1,name2:path2`. Empty/missing → `Ok(vec![])`.
pub fn parse_env_spec(env_value: Option<&str>) -> Vec<(String, PathBuf)> {
    match env_value {
        None | Some("") => Vec::new(),
        Some(s) => s
            .split(',')
            .filter_map(|entry| {
                let mut parts = entry.splitn(2, ':');
                let name = parts.next()?.trim().to_string();
                let path = parts.next()?.trim().to_string();
                if name.is_empty() || path.is_empty() {
                    None
                } else {
                    Some((name, PathBuf::from(path)))
                }
            })
            .collect(),
    }
}

#[cfg(test)]
mod tokenize_golden_tests {
    use super::*;
    use crate::evidence::EvalInput;

    /// DET-REASONING-1: lock the FNV-1a tokenizer output. The feature vector
    /// feeds the signed `ml_scores`; a toolchain/target change or an accidental
    /// hash swap that would silently re-bucket the trigrams (and so change the
    /// signed receipt) is caught here. Buckets are the trigrams of "sentinel".
    #[test]
    fn tokenize_is_byte_stable_golden() {
        let input = EvalInput::new("a", "t", "http", "sentinel");
        let feats = tokenize(&input);
        assert_eq!(feats.len(), INPUT_DIM);

        let mut expected = vec![0.0f32; INPUT_DIM];
        expected[33] = 0.5;
        expected[34] = 0.5;
        expected[48] = 1.0; // two trigrams collide here -> the max
        expected[49] = 0.5;
        expected[58] = 0.5;
        assert_eq!(feats, expected, "FNV-1a tokenizer buckets drifted");

        // Determinism: identical input yields the identical vector.
        assert_eq!(tokenize(&input), feats);
    }

    #[test]
    fn tokenize_short_input_is_all_zero() {
        let input = EvalInput::new("a", "t", "http", "ab");
        assert_eq!(tokenize(&input), vec![0.0f32; INPUT_DIM]);
    }

    /// DET-REASONING-2: the f32→signed-score quantization is on a fixed 1e-6
    /// grid, so two ULP-apart f32 outputs collapse to the same signed value.
    #[test]
    fn quantize_score_is_on_a_micro_grid() {
        assert_eq!(quantize_score(0.5), 0.5);
        assert_eq!(quantize_score(0.0), 0.0);
        // The result is an integer number of micro-units over 1e6.
        assert_eq!(quantize_score(0.333_333_4_f32), 333_333.0 / 1_000_000.0);
        // Two ULP-apart f32 inputs collapse to the same signed value.
        assert_eq!(
            quantize_score(0.333_333_4_f32),
            quantize_score(0.333_333_45_f32)
        );
    }
}
