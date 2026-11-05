//! Recursive-descent parser for the policy DSL.
//!
//! Parsing is a pure function of the source text. Recursion is guarded by
//! [`MAX_NESTING`](super::error::MAX_NESTING), so hostile nesting cannot
//! exhaust the native stack.

use std::collections::BTreeSet;

use super::ast::{BinOp, Expr, UnOp};
use super::error::{PolicyError, MAX_INSTRUCTIONS, MAX_LIST, MAX_NESTING, MAX_ORACLES};
use super::lexer::{lex, Token, TokenKind};
use super::{OracleDecl, Type};

/// A parsed (but not yet compiled) policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub name: String,
    pub oracles: Vec<OracleDecl>,
    pub allow: Expr,
}

/// Parse source text into a [`Program`].
pub fn parse(source: &str) -> Result<Program, PolicyError> {
    let tokens = lex(source)?;
    let mut parser = Parser {
        tokens,
        pos: 0,
        depth: 0,
        nodes: 0,
    };
    parser.parse_policy()
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    depth: usize,
    /// Number of expression nodes built so far. Bounded by the bytecode
    /// instruction cap so the AST (and its recursive drop) stays bounded even
    /// for long left-associative chains that never hit `MAX_NESTING`.
    nodes: usize,
}

impl Parser {
    fn peek(&self) -> &TokenKind {
        // `lex` always appends `Eof`, and `advance` never moves past it.
        &self.tokens[self.pos].kind
    }

    fn offset(&self) -> usize {
        self.tokens[self.pos].offset
    }

    fn advance(&mut self) {
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
    }

    fn unexpected(&self, expected: &str) -> PolicyError {
        let found = self.peek();
        if *found == TokenKind::Eof {
            PolicyError::UnexpectedEof {
                expected: expected.to_string(),
            }
        } else {
            PolicyError::UnexpectedToken {
                offset: self.offset(),
                expected: expected.to_string(),
                found: found.describe(),
            }
        }
    }

    fn expect(&mut self, kind: TokenKind, label: &str) -> Result<(), PolicyError> {
        if *self.peek() == kind {
            self.advance();
            Ok(())
        } else {
            Err(self.unexpected(label))
        }
    }

    fn take_ident(&mut self) -> Result<String, PolicyError> {
        if let TokenKind::Ident(name) = self.peek() {
            let name = name.clone();
            self.advance();
            Ok(name)
        } else {
            Err(self.unexpected("identifier"))
        }
    }

    fn take_string(&mut self) -> Result<String, PolicyError> {
        if let TokenKind::Str(value) = self.peek() {
            let value = value.clone();
            self.advance();
            Ok(value)
        } else {
            Err(self.unexpected("string"))
        }
    }

    fn enter(&mut self) -> Result<(), PolicyError> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            return Err(PolicyError::NestingTooDeep { max: MAX_NESTING });
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Account for one expression node and enforce the global AST bound.
    ///
    /// Every program needs at least one bytecode instruction per AST node, so
    /// this cap can never reject a policy that would otherwise compile.
    fn node(&mut self, expr: Expr) -> Result<Expr, PolicyError> {
        self.nodes += 1;
        if self.nodes > MAX_INSTRUCTIONS {
            return Err(PolicyError::TooManyInstructions {
                count: self.nodes,
                max: MAX_INSTRUCTIONS,
            });
        }
        Ok(expr)
    }

    fn parse_policy(&mut self) -> Result<Program, PolicyError> {
        self.expect(TokenKind::Policy, "`policy`")?;
        let name = self.take_string()?;
        self.expect(TokenKind::LBrace, "`{`")?;

        let mut oracles = Vec::new();
        let mut seen = BTreeSet::new();
        while *self.peek() == TokenKind::Oracle {
            self.advance();
            let oracle_name = self.take_ident()?;
            if !seen.insert(oracle_name.clone()) {
                return Err(PolicyError::DuplicateOracle { name: oracle_name });
            }
            self.expect(TokenKind::Colon, "`:`")?;
            let ty = self.parse_type()?;
            self.expect(TokenKind::Semi, "`;`")?;
            oracles.push(OracleDecl {
                name: oracle_name,
                ty,
            });
            if oracles.len() > MAX_ORACLES {
                return Err(PolicyError::TooManyOracles {
                    count: oracles.len(),
                    max: MAX_ORACLES,
                });
            }
        }

        self.expect(TokenKind::Allow, "`allow`")?;
        let allow = self.parse_or()?;
        // The trailing semicolon is optional so both `allow x }` and
        // `allow x; }` are accepted (the latter reads better in long policies).
        if *self.peek() == TokenKind::Semi {
            self.advance();
        }
        self.expect(TokenKind::RBrace, "`}`")?;
        self.expect(TokenKind::Eof, "end of input")?;

        Ok(Program {
            name,
            oracles,
            allow,
        })
    }

    fn parse_type(&mut self) -> Result<Type, PolicyError> {
        match self.peek() {
            TokenKind::IntType => {
                self.advance();
                Ok(Type::Int)
            }
            TokenKind::BoolType => {
                self.advance();
                Ok(Type::Bool)
            }
            TokenKind::BytesType => {
                self.advance();
                Ok(Type::Bytes)
            }
            _ => Err(self.unexpected("`int`, `bool`, or `bytes`")),
        }
    }

    fn parse_or(&mut self) -> Result<Expr, PolicyError> {
        let mut left = self.parse_and()?;
        while *self.peek() == TokenKind::OrOr {
            self.advance();
            let right = self.parse_and()?;
            left = self.node(Expr::Binary(BinOp::Or, Box::new(left), Box::new(right)))?;
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, PolicyError> {
        let mut left = self.parse_cmp()?;
        while *self.peek() == TokenKind::AndAnd {
            self.advance();
            let right = self.parse_cmp()?;
            left = self.node(Expr::Binary(BinOp::And, Box::new(left), Box::new(right)))?;
        }
        Ok(left)
    }

    fn parse_cmp(&mut self) -> Result<Expr, PolicyError> {
        let left = self.parse_add()?;
        let op = match self.peek() {
            TokenKind::EqEq => BinOp::Eq,
            TokenKind::NotEq => BinOp::Ne,
            TokenKind::Lt => BinOp::Lt,
            TokenKind::Le => BinOp::Le,
            TokenKind::Gt => BinOp::Gt,
            TokenKind::Ge => BinOp::Ge,
            TokenKind::In => BinOp::In,
            _ => return Ok(left),
        };
        self.advance();

        // `in` requires a list literal on the right; this keeps the element
        // type inferable during compilation.
        if op == BinOp::In {
            let right = self.parse_list()?;
            return self.node(Expr::Binary(BinOp::In, Box::new(left), Box::new(right)));
        }

        let right = self.parse_add()?;
        self.node(Expr::Binary(op, Box::new(left), Box::new(right)))
    }

    fn parse_add(&mut self) -> Result<Expr, PolicyError> {
        let mut left = self.parse_mul()?;
        loop {
            let op = match self.peek() {
                TokenKind::Plus => BinOp::Add,
                TokenKind::Minus => BinOp::Sub,
                _ => break,
            };
            self.advance();
            let right = self.parse_mul()?;
            left = self.node(Expr::Binary(op, Box::new(left), Box::new(right)))?;
        }
        Ok(left)
    }

    fn parse_mul(&mut self) -> Result<Expr, PolicyError> {
        let mut left = self.parse_unary()?;
        while *self.peek() == TokenKind::Star {
            self.advance();
            let right = self.parse_unary()?;
            left = self.node(Expr::Binary(BinOp::Mul, Box::new(left), Box::new(right)))?;
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, PolicyError> {
        match self.peek() {
            TokenKind::Bang => {
                self.enter()?;
                self.advance();
                let inner = self.parse_unary()?;
                self.leave();
                self.node(Expr::Unary(UnOp::Not, Box::new(inner)))
            }
            TokenKind::Minus => {
                self.enter()?;
                self.advance();
                let inner = self.parse_unary()?;
                self.leave();
                self.node(Expr::Unary(UnOp::Neg, Box::new(inner)))
            }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, PolicyError> {
        match self.peek().clone() {
            TokenKind::Int(value) => {
                self.advance();
                self.node(Expr::Int(value))
            }
            TokenKind::True => {
                self.advance();
                self.node(Expr::Bool(true))
            }
            TokenKind::False => {
                self.advance();
                self.node(Expr::Bool(false))
            }
            TokenKind::Bytes(value) => {
                self.advance();
                self.node(Expr::Bytes(value))
            }
            TokenKind::Ident(name) => {
                self.advance();
                self.node(Expr::Oracle(name))
            }
            TokenKind::LParen => {
                self.enter()?;
                self.advance();
                let inner = self.parse_or()?;
                self.expect(TokenKind::RParen, "`)`")?;
                self.leave();
                Ok(inner)
            }
            TokenKind::LBracket => self.parse_list(),
            TokenKind::Count => {
                self.enter()?;
                self.advance();
                self.expect(TokenKind::LParen, "`(`")?;
                let inner = self.parse_or()?;
                self.expect(TokenKind::RParen, "`)`")?;
                self.leave();
                self.node(Expr::Count(Box::new(inner)))
            }
            _ => Err(self.unexpected("expression")),
        }
    }

    fn parse_list(&mut self) -> Result<Expr, PolicyError> {
        self.enter()?;
        self.expect(TokenKind::LBracket, "`[`")?;
        if *self.peek() == TokenKind::RBracket {
            return Err(PolicyError::EmptyList);
        }

        let mut items = Vec::new();
        loop {
            items.push(self.parse_or()?);
            if items.len() > MAX_LIST {
                return Err(PolicyError::ListTooLong {
                    count: items.len(),
                    max: MAX_LIST,
                });
            }
            if *self.peek() == TokenKind::Comma {
                self.advance();
                continue;
            }
            break;
        }
        self.expect(TokenKind::RBracket, "`]`")?;
        self.leave();
        self.node(Expr::List(items))
    }
}
