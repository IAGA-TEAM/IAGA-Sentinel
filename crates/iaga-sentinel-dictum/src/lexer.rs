//! Lexer for Dictum. Implemented with `logos` for speed and compact
//! error handling. Whitespace and `//`-line comments are skipped.

use logos::Logos;

#[derive(Logos, Debug, Clone, PartialEq)]
#[logos(skip r"[ \t\r\n\f]+")]
#[logos(skip r"//[^\n]*")]
pub enum Token {
    // keywords
    #[token("policy")]
    Policy,
    #[token("when")]
    When,
    #[token("then")]
    Then,
    #[token("allow")]
    Allow,
    #[token("review")]
    Review,
    #[token("block")]
    Block,
    #[token("reason")]
    Reason,
    #[token("evidence")]
    Evidence,
    #[token("and")]
    And,
    #[token("or")]
    Or,
    #[token("not")]
    Not,
    #[token("in")]
    In,
    #[token("true")]
    True,
    #[token("false")]
    False,

    // punctuation
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token(",")]
    Comma,
    #[token(".")]
    Dot,
    #[token("=")]
    Eq,
    #[token("==")]
    EqEq,
    #[token("!=")]
    NotEq,
    #[token("<=")]
    LtEq,
    #[token(">=")]
    GtEq,
    #[token("<")]
    Lt,
    #[token(">")]
    Gt,

    // literals
    #[regex(r#""([^"\\]|\\["\\nrt])*""#, |lex| unescape(lex.slice()))]
    Str(String),

    #[regex(r"-?[0-9]+", |lex| lex.slice().parse::<i64>().ok())]
    Int(i64),

    #[regex(r"[a-zA-Z_][a-zA-Z0-9_]*", |lex| lex.slice().to_string())]
    Ident(String),
}

fn unescape(raw: &str) -> Option<String> {
    // strip surrounding quotes
    let inner = &raw[1..raw.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next()? {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                other => {
                    // unknown escape: keep literal (permissive for MVP)
                    out.push('\\');
                    out.push(other);
                }
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// Tokenize the input into `(Token, line, col)` tuples. Lines are
/// 1-based; columns are 1-based and count the starting character of
/// the token. Bad tokens raise a `ParseError` at the caller site.
pub fn tokenize(src: &str) -> Result<Vec<(Token, u32, u32)>, crate::errors::DictumError> {
    use crate::errors::DictumError;

    // Tolerate a leading UTF-8 BOM: editors (and PowerShell's `Set-Content
    // -Encoding utf8` on 5.1) prepend one, and without this the lexer reports
    // `unexpected character` at 1:1 on a policy that is otherwise perfectly valid.
    let src = src.strip_prefix('\u{feff}').unwrap_or(src);

    let mut lex = Token::lexer(src);
    let mut out = Vec::new();
    while let Some(res) = lex.next() {
        let span = lex.span();
        let (line, col) = line_col(src, span.start);
        match res {
            Ok(tok) => out.push((tok, line, col)),
            Err(_) => {
                return Err(DictumError::Parse {
                    line,
                    col,
                    msg: format!("unexpected character `{}`", &src[span]),
                });
            }
        }
    }
    Ok(out)
}

fn line_col(src: &str, byte_offset: usize) -> (u32, u32) {
    let mut line = 1u32;
    let mut col = 1u32;
    for (i, c) in src.char_indices() {
        if i >= byte_offset {
            break;
        }
        if c == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_utf8_bom_is_tolerated() {
        // A BOM-prefixed source must tokenize identically to the same source
        // without one — editors and PowerShell add a BOM to .dictum files.
        let src = r#"policy "p" { when true then allow }"#;
        let with_bom = format!("\u{feff}{src}");
        let a = tokenize(src).expect("plain source tokenizes");
        let b = tokenize(&with_bom).expect("BOM-prefixed source must tokenize");
        let toks_a: Vec<_> = a.iter().map(|(t, _, _)| t.clone()).collect();
        let toks_b: Vec<_> = b.iter().map(|(t, _, _)| t.clone()).collect();
        assert_eq!(toks_a, toks_b);
    }
}
