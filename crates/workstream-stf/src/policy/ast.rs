//! Expression tree produced by the parser.
//!
//! The tree is a bounded, finite representation of the source: no cycles, no
//! references, and its depth is capped by the parser's nesting guard.

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Not,
    Neg,
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    And,
    Or,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    In,
}

/// A policy expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Int(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    /// Reference to a declared oracle.
    Oracle(String),
    /// A non-empty, homogeneous list literal.
    List(Vec<Expr>),
    Unary(UnOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// `count(list<bool>)`.
    Count(Box<Expr>),
}
