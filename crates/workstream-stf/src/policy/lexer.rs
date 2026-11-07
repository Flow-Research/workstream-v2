//! Byte-oriented lexer for the policy DSL.
//!
//! The lexer never panics on untrusted input: every failure is a
//! [`PolicyError`] carrying a byte offset. Identifiers are ASCII; strings may
//! contain arbitrary valid UTF-8, and byte literals are hex.

use super::error::{PolicyError, MAX_BYTES, MAX_NAME_LEN};
use super::MAX_IDENT_LEN;

/// A lexical token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    Policy,
    Oracle,
    Allow,
    IntType,
    BoolType,
    BytesType,
    True,
    False,
    Count,
    In,

    Ident(String),
    Int(i64),
    Bytes(Vec<u8>),
    Str(String),

    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Semi,
    Colon,

    Plus,
    Minus,
    Star,
    Bang,
    AndAnd,
    OrOr,
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,

    Eof,
}

impl TokenKind {
    /// Human-readable description used in parser errors.
    pub fn describe(&self) -> String {
        match self {
            TokenKind::Policy => "`policy`".to_string(),
            TokenKind::Oracle => "`oracle`".to_string(),
            TokenKind::Allow => "`allow`".to_string(),
            TokenKind::IntType => "`int`".to_string(),
            TokenKind::BoolType => "`bool`".to_string(),
            TokenKind::BytesType => "`bytes`".to_string(),
            TokenKind::True => "`true`".to_string(),
            TokenKind::False => "`false`".to_string(),
            TokenKind::Count => "`count`".to_string(),
            TokenKind::In => "`in`".to_string(),
            TokenKind::Ident(name) => format!("identifier {name:?}"),
            TokenKind::Int(value) => format!("integer {value}"),
            TokenKind::Bytes(value) => format!("bytes literal ({} bytes)", value.len()),
            TokenKind::Str(value) => format!("string {value:?}"),
            TokenKind::LBrace => "`{`".to_string(),
            TokenKind::RBrace => "`}`".to_string(),
            TokenKind::LParen => "`(`".to_string(),
            TokenKind::RParen => "`)`".to_string(),
            TokenKind::LBracket => "`[`".to_string(),
            TokenKind::RBracket => "`]`".to_string(),
            TokenKind::Comma => "`,`".to_string(),
            TokenKind::Semi => "`;`".to_string(),
            TokenKind::Colon => "`:`".to_string(),
            TokenKind::Plus => "`+`".to_string(),
            TokenKind::Minus => "`-`".to_string(),
            TokenKind::Star => "`*`".to_string(),
            TokenKind::Bang => "`!`".to_string(),
            TokenKind::AndAnd => "`&&`".to_string(),
            TokenKind::OrOr => "`||`".to_string(),
            TokenKind::EqEq => "`==`".to_string(),
            TokenKind::NotEq => "`!=`".to_string(),
            TokenKind::Lt => "`<`".to_string(),
            TokenKind::Le => "`<=`".to_string(),
            TokenKind::Gt => "`>`".to_string(),
            TokenKind::Ge => "`>=`".to_string(),
            TokenKind::Eof => "end of input".to_string(),
        }
    }
}

/// A token plus its byte offset in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub offset: usize,
}

/// Reserved words cannot be used as identifiers.
pub fn is_reserved(word: &str) -> bool {
    matches!(
        word,
        "policy"
            | "oracle"
            | "allow"
            | "int"
            | "bool"
            | "bytes"
            | "true"
            | "false"
            | "count"
            | "in"
    )
}

/// Validate an identifier without allocating.
pub fn is_valid_ident(word: &str) -> bool {
    let bytes = word.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_IDENT_LEN || is_reserved(word) {
        return false;
    }
    if !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_') {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// Tokenize a policy source string.
pub fn lex(source: &str) -> Result<Vec<Token>, PolicyError> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        let byte = bytes[i];
        match byte {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'{' => {
                tokens.push(single(TokenKind::LBrace, i));
                i += 1;
            }
            b'}' => {
                tokens.push(single(TokenKind::RBrace, i));
                i += 1;
            }
            b'(' => {
                tokens.push(single(TokenKind::LParen, i));
                i += 1;
            }
            b')' => {
                tokens.push(single(TokenKind::RParen, i));
                i += 1;
            }
            b'[' => {
                tokens.push(single(TokenKind::LBracket, i));
                i += 1;
            }
            b']' => {
                tokens.push(single(TokenKind::RBracket, i));
                i += 1;
            }
            b',' => {
                tokens.push(single(TokenKind::Comma, i));
                i += 1;
            }
            b';' => {
                tokens.push(single(TokenKind::Semi, i));
                i += 1;
            }
            b':' => {
                tokens.push(single(TokenKind::Colon, i));
                i += 1;
            }
            b'+' => {
                tokens.push(single(TokenKind::Plus, i));
                i += 1;
            }
            b'-' => {
                tokens.push(single(TokenKind::Minus, i));
                i += 1;
            }
            b'*' => {
                tokens.push(single(TokenKind::Star, i));
                i += 1;
            }
            b'!' if bytes.get(i + 1) == Some(&b'=') => {
                tokens.push(single(TokenKind::NotEq, i));
                i += 2;
            }
            b'!' => {
                tokens.push(single(TokenKind::Bang, i));
                i += 1;
            }
            b'&' if bytes.get(i + 1) == Some(&b'&') => {
                tokens.push(single(TokenKind::AndAnd, i));
                i += 2;
            }
            b'|' if bytes.get(i + 1) == Some(&b'|') => {
                tokens.push(single(TokenKind::OrOr, i));
                i += 2;
            }
            b'=' if bytes.get(i + 1) == Some(&b'=') => {
                tokens.push(single(TokenKind::EqEq, i));
                i += 2;
            }
            b'<' if bytes.get(i + 1) == Some(&b'=') => {
                tokens.push(single(TokenKind::Le, i));
                i += 2;
            }
            b'<' => {
                tokens.push(single(TokenKind::Lt, i));
                i += 1;
            }
            b'>' if bytes.get(i + 1) == Some(&b'=') => {
                tokens.push(single(TokenKind::Ge, i));
                i += 2;
            }
            b'>' => {
                tokens.push(single(TokenKind::Gt, i));
                i += 1;
            }
            b'"' => {
                let (value, next) = read_string(source, i)?;
                tokens.push(Token {
                    kind: TokenKind::Str(value),
                    offset: i,
                });
                i = next;
            }
            b'0'..=b'9' => {
                let (kind, next) = read_number(source, i)?;
                tokens.push(Token { kind, offset: i });
                i = next;
            }
            b'A'..=b'Z' | b'a'..=b'z' | b'_' => {
                let (kind, next) = read_ident(source, i)?;
                tokens.push(Token { kind, offset: i });
                i = next;
            }
            _ => {
                // `i` is at a char boundary because ASCII bytes advance by one
                // and the only multi-byte tokens are consumed whole above.
                let ch = source[i..].chars().next().unwrap_or('\u{FFFD}');
                return Err(PolicyError::InvalidCharacter { offset: i, ch });
            }
        }
    }

    tokens.push(Token {
        kind: TokenKind::Eof,
        offset: source.len(),
    });
    Ok(tokens)
}

fn single(kind: TokenKind, offset: usize) -> Token {
    Token { kind, offset }
}

fn read_number(source: &str, start: usize) -> Result<(TokenKind, usize), PolicyError> {
    let bytes = source.as_bytes();
    let mut i = start;

    if bytes[i] == b'0' && matches!(bytes.get(i + 1), Some(b'x' | b'X')) {
        return read_bytes_literal(source, start);
    }

    let mut value: i64 = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        let digit = i64::from(bytes[i] - b'0');
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or(PolicyError::InvalidNumber { offset: start })?;
        i += 1;
    }
    Ok((TokenKind::Int(value), i))
}

fn read_bytes_literal(source: &str, start: usize) -> Result<(TokenKind, usize), PolicyError> {
    let bytes = source.as_bytes();
    let mut i = start + 2;
    let mut nibbles = Vec::new();
    while i < bytes.len() {
        match bytes[i] {
            b'0'..=b'9' => nibbles.push(bytes[i] - b'0'),
            b'a'..=b'f' => nibbles.push(bytes[i] - b'a' + 10),
            b'A'..=b'F' => nibbles.push(bytes[i] - b'A' + 10),
            _ => break,
        }
        i += 1;
    }

    if nibbles.len() % 2 != 0 {
        return Err(PolicyError::InvalidBytes {
            offset: start,
            reason: "hex literal has an odd number of digits".to_string(),
        });
    }

    let len = nibbles.len() / 2;
    if len > MAX_BYTES {
        return Err(PolicyError::BytesTooLong {
            len,
            max: MAX_BYTES,
        });
    }

    let mut value = Vec::with_capacity(len);
    let (pairs, remainder) = nibbles.as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for pair in pairs {
        value.push((pair[0] << 4) | pair[1]);
    }
    Ok((TokenKind::Bytes(value), i))
}

fn read_string(source: &str, start: usize) -> Result<(String, usize), PolicyError> {
    let bytes = source.as_bytes();
    let mut i = start + 1;
    let mut value = Vec::new();

    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let text = String::from_utf8(value).map_err(|_| PolicyError::InvalidString {
                    offset: start,
                    reason: "invalid UTF-8".to_string(),
                })?;
                if text.len() > MAX_NAME_LEN {
                    return Err(PolicyError::NameTooLong {
                        len: text.len(),
                        max: MAX_NAME_LEN,
                    });
                }
                return Ok((text, i + 1));
            }
            b'\\' => {
                i += 1;
                match bytes.get(i) {
                    Some(b'"') => value.push(b'"'),
                    Some(b'\\') => value.push(b'\\'),
                    Some(_) => {
                        return Err(PolicyError::InvalidString {
                            offset: i - 1,
                            reason: "only \\\" and \\\\ escapes are supported".to_string(),
                        })
                    }
                    None => {
                        return Err(PolicyError::UnexpectedEof {
                            expected: "closing quote".to_string(),
                        })
                    }
                }
                i += 1;
            }
            byte if byte < 0x20 => {
                return Err(PolicyError::InvalidString {
                    offset: i,
                    reason: "control characters are not allowed".to_string(),
                })
            }
            byte => {
                value.push(byte);
                i += 1;
            }
        }
    }

    Err(PolicyError::UnexpectedEof {
        expected: "closing quote".to_string(),
    })
}

fn read_ident(source: &str, start: usize) -> Result<(TokenKind, usize), PolicyError> {
    let bytes = source.as_bytes();
    let mut i = start;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }

    let len = i - start;
    if len > MAX_IDENT_LEN {
        return Err(PolicyError::IdentifierTooLong {
            len,
            max: MAX_IDENT_LEN,
        });
    }

    // ASCII-only by construction; the error arm is unreachable defense.
    let word =
        std::str::from_utf8(&bytes[start..i]).map_err(|_| PolicyError::InvalidCharacter {
            offset: start,
            ch: '\u{FFFD}',
        })?;
    let kind = match word {
        "policy" => TokenKind::Policy,
        "oracle" => TokenKind::Oracle,
        "allow" => TokenKind::Allow,
        "int" => TokenKind::IntType,
        "bool" => TokenKind::BoolType,
        "bytes" => TokenKind::BytesType,
        "true" => TokenKind::True,
        "false" => TokenKind::False,
        "count" => TokenKind::Count,
        "in" => TokenKind::In,
        _ => TokenKind::Ident(word.to_string()),
    };
    Ok((kind, i))
}
