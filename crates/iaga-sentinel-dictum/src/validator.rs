//! Structural validator for Dictum programs.
//!
//! This is **not** a full type checker. For M3 the evaluator is
//! dynamically typed against a JSON-ish `Value`, runtime errors from
//! type mismatches are normal and produce `DictumError::Eval`. What this
//! validator enforces are *structural* invariants that catch obvious
//! mistakes before eval time:
//!
//! - policy names are non-empty and unique,
//! - every policy has a non-empty `when` expression,
//! - known builtin calls have the right arity,
//! - identifier paths have non-empty head segments.
//!
//! A full Hindley-Milner style type checker is an M3.1 follow-up and
//! will share the AST.

use std::collections::HashSet;

use crate::ast::*;
use crate::errors::{DictumError, Result};

const BUILTIN_ARITIES: &[(&str, usize)] = &[
    ("contains", 2),
    ("starts_with", 2),
    ("ends_with", 2),
    ("len", 1),
    ("lower", 1),
    ("upper", 1),
    ("secret_ref", 1),
    ("url_host", 1),
    ("timestamp", 1),
    ("sha256", 1),
];

pub fn validate(program: &Program) -> Result<()> {
    let mut seen = HashSet::new();
    for p in &program.policies {
        if p.name.trim().is_empty() {
            return Err(DictumError::Type(
                "policy name must be a non-empty string".into(),
            ));
        }
        if !seen.insert(p.name.clone()) {
            return Err(DictumError::Type(format!(
                "duplicate policy name: {}",
                p.name
            )));
        }
        validate_expr(&p.when)?;
        if let Some(ev) = &p.action.evidence {
            validate_expr(ev)?;
        }
    }
    Ok(())
}

fn validate_expr(e: &Expr) -> Result<()> {
    match e {
        Expr::Lit(_) => Ok(()),
        Expr::Path(segs) => {
            if segs.is_empty() {
                return Err(DictumError::Type("empty identifier path".into()));
            }
            Ok(())
        }
        Expr::Call(name, args) => {
            if let Some((_, arity)) = BUILTIN_ARITIES.iter().find(|(n, _)| n == name) {
                if args.len() != *arity {
                    return Err(DictumError::Type(format!(
                        "builtin `{}` takes {} args, got {}",
                        name,
                        arity,
                        args.len()
                    )));
                }
            }
            // unknown-name calls pass through, user extensions can
            // register dynamic builtins at eval time.
            for a in args {
                validate_expr(a)?;
            }
            Ok(())
        }
        Expr::Binary(_, l, r) => {
            validate_expr(l)?;
            validate_expr(r)
        }
        Expr::Unary(_, inner) => validate_expr(inner),
        Expr::Membership {
            needle, haystack, ..
        } => {
            validate_expr(needle)?;
            validate_expr(haystack)
        }
    }
}

/// Every context path a program references, from both `when` and `evidence`,
/// in source order and including duplicates.
///
/// This crate is host-agnostic: it cannot know which paths a given embedder
/// will actually populate. The host does, and uses this to reject a policy
/// that references a field its runtime context can never provide. That check
/// belongs at load time, because at eval time a missing path resolves to
/// `Null` and an ordering comparison against `Null` is an eval error, which
/// [`crate::eval::evaluate_program_traced`] deliberately turns into a
/// fail-closed fire — correct against a hostile payload, but a very confusing
/// way to learn you typed `action.risk_score` instead of `risk.score`.
pub fn collect_paths(program: &Program) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for p in &program.policies {
        collect_expr_paths(&p.when, &mut out);
        if let Some(ev) = &p.action.evidence {
            collect_expr_paths(ev, &mut out);
        }
    }
    out
}

fn collect_expr_paths(e: &Expr, out: &mut Vec<Vec<String>>) {
    match e {
        Expr::Lit(_) => {}
        Expr::Path(segs) => out.push(segs.clone()),
        Expr::Call(_, args) => {
            for a in args {
                collect_expr_paths(a, out);
            }
        }
        Expr::Binary(_, l, r) => {
            collect_expr_paths(l, out);
            collect_expr_paths(r, out);
        }
        Expr::Unary(_, inner) => collect_expr_paths(inner, out),
        Expr::Membership {
            needle, haystack, ..
        } => {
            collect_expr_paths(needle, out);
            collect_expr_paths(haystack, out);
        }
    }
}

#[cfg(test)]
mod collect_tests {
    use super::*;

    #[test]
    fn collects_paths_from_when_and_evidence() {
        let src = r#"
            policy "p" {
              when action.kind == "http"
               and url_host(action.payload.destination) not in workspace.allowlist
              then block, reason="r", evidence=action.payload.destination
            }
        "#;
        let program = crate::parse(src).expect("parses");
        let paths = collect_paths(&program);
        let joined: Vec<String> = paths.iter().map(|p| p.join(".")).collect();
        assert!(joined.contains(&"action.kind".to_string()));
        assert!(joined.contains(&"action.payload.destination".to_string()));
        assert!(joined.contains(&"workspace.allowlist".to_string()));
        // evidence is walked too
        assert!(joined.iter().filter(|p| *p == "action.payload.destination").count() >= 2);
    }
}
