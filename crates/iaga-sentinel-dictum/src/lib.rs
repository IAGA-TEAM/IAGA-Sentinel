//! # iaga-sentinel-dictum
//!
//! Dictum (formerly APL / Agent Policy Language), MVP for 1.0 M3.
//!
//! Dictum is a typed DSL that replaces 0.4.0's YAML + template pipeline
//! for policy authoring. This crate ships:
//!
//! - a `logos`-based lexer,
//! - a recursive-descent parser producing a [`Program`] AST,
//! - a structural validator (see [`validate`]),
//! - a deterministic tree-walk evaluator with an instruction budget.
//!
//! **Scope note (M3 MVP)**: the long-term Dictum design calls for
//! WASM bytecode as an execution target. For M3 we ship a tree-walk
//! interpreter that is pure and deterministic (no I/O, no wall clock,
//! no RNG, single-threaded). This is already sufficient for receipt
//! replay: given the same AST and context, eval yields the same result.
//! WASM codegen is planned for M3.1 and will slot in behind the same
//! evaluator entrypoints without AST changes.
//!
//! Example policy:
//!
//! ```text
//! policy "no_secrets_to_public_http" {
//!   when action.kind == "http"
//!    and url_host(action.payload.destination) not in workspace.allowlist
//!    and secret_ref(action.payload)
//!   then block, reason="PII egress"
//! }
//! ```
//!
//! See `docs/adr/0004-dictum-mvp.md` for the full design rationale.

pub mod ast;
pub mod errors;
pub mod eval;
pub mod lexer;
pub mod parser;
mod secrets;
pub mod types;
pub mod validator;

#[cfg(feature = "dictum-wasm")]
pub mod wasm;

pub use ast::{Action, BinOp, Expr, Lit, Policy, Program, UnOp, Verdict};
pub use errors::{DictumError, Result};
pub use eval::{
    eval_expr, evaluate_program, evaluate_program_traced, Context, EvalBudget, EvalTrace,
    PolicyFired, Value,
};
pub use parser::parse;
pub use types::{infer, Ty, TypeEnv, TypeError};
pub use validator::{collect_paths, validate};

#[cfg(feature = "dictum-wasm")]
pub use wasm::{compile_to_wasm, WasmCompileError, WasmProgram};

/// Parse and validate in one shot. Most hosts want this:
/// eval comes later with a concrete context.
pub fn compile(src: &str) -> Result<Program> {
    let program = parse(src)?;
    validate(&program)?;
    Ok(program)
}

/// 1.2 OSS, parse, validate, and infer types. Companion to
/// [`compile`] that additionally runs the Hindley-Milner type
/// checker (ADR 0014). Returns both the program AST and the
/// inferred [`TypeEnv`] so hosts can introspect the per-policy
/// `when` types.
///
/// Type errors are reported as [`TypeError`] alongside the standard
/// [`DictumError`] (parse / validate). Hosts that only want the syntactic
/// pipeline should keep using [`compile`].
pub fn compile_with_types(src: &str) -> std::result::Result<(Program, TypeEnv), CompileError> {
    let program = parse(src).map_err(CompileError::Dictum)?;
    validate(&program).map_err(CompileError::Dictum)?;
    let env = infer(&program).map_err(CompileError::Type)?;
    Ok((program, env))
}

/// Aggregate error for [`compile_with_types`]: either a parse/validate
/// failure ([`DictumError`]) or a type-inference failure ([`TypeError`]).
#[derive(Debug)]
pub enum CompileError {
    Dictum(DictumError),
    Type(TypeError),
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::Dictum(e) => write!(f, "{e}"),
            CompileError::Type(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CompileError {}
