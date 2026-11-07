//! Bounded, total, deterministic policy DSL (issues #26 / #27).
//!
//! See `docs/design/policy-dsl.md` for the full contract. In short:
//!
//! - policies compile to a straight-line stack bytecode with no loops or
//!   jumps;
//! - bytecode is canonical and hash-locked by [`Policy::id`];
//! - external facts are declared oracles, typed and looked up in a
//!   [`BTreeMap`];
//! - evaluation is total: it returns a boolean or a [`PolicyError`], never
//!   panics.
//!
//! ```ignore
//! let policy = Policy::compile(r#"
//!     policy "eligibility" {
//!         oracle reputation: int;
//!         oracle allowlisted: bool;
//!         allow allowlisted && reputation >= 50;
//!     }
//! "#).unwrap();
//!
//! let mut oracles = OracleInput::new();
//! oracles.insert("reputation".into(), Value::Int(75));
//! oracles.insert("allowlisted".into(), Value::Bool(true));
//! assert_eq!(policy.evaluate(&oracles).unwrap(), true);
//! ```

mod ast;
mod bytecode;
mod error;
mod interp;
mod lexer;
mod parser;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

pub use bytecode::Instr;
pub use error::{
    PolicyError, MAX_BYTES, MAX_INSTRUCTIONS, MAX_LIST, MAX_NAME_LEN, MAX_NESTING, MAX_ORACLES,
    MAX_ORACLE_INPUTS, MAX_SOURCE_LEN, MAX_STACK,
};
pub use workstream_core::types::PolicyId;

/// Maximum identifier length (oracle names).
pub const MAX_IDENT_LEN: usize = 64;

/// A policy type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    Int,
    Bool,
    Bytes,
    /// Internal list type; never an oracle type and never the final result.
    List(Box<Type>),
}

impl Type {
    /// Whether this type may appear as a scalar value (list elements, oracle
    /// declarations, equality operands).
    pub fn is_scalar(&self) -> bool {
        !matches!(self, Type::List(_))
    }

    /// Canonical oracle type tag used in bytecode.
    fn tag(&self) -> u8 {
        match self {
            Type::Int => 0,
            Type::Bool => 1,
            Type::Bytes => 2,
            // Not producible by the compiler or accepted by the decoder.
            // Keeping a total function avoids panics in encoding paths.
            Type::List(_) => 3,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, PolicyError> {
        match tag {
            0 => Ok(Type::Int),
            1 => Ok(Type::Bool),
            2 => Ok(Type::Bytes),
            _ => Err(PolicyError::Corrupt("invalid oracle type tag")),
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Int => f.write_str("int"),
            Type::Bool => f.write_str("bool"),
            Type::Bytes => f.write_str("bytes"),
            Type::List(element) => write!(f, "list<{element}>"),
        }
    }
}

/// A runtime policy value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    List(Vec<Value>),
}

impl Value {
    /// The type of this value.
    pub fn type_of(&self) -> Type {
        match self {
            Value::Int(_) => Type::Int,
            Value::Bool(_) => Type::Bool,
            Value::Bytes(_) => Type::Bytes,
            Value::List(items) => {
                let element = items.first().map(Value::type_of).unwrap_or(Type::Bool);
                Type::List(Box::new(element))
            }
        }
    }

    /// Whether this value satisfies a declared type.
    pub fn matches(&self, ty: &Type) -> bool {
        match (self, ty) {
            (Value::Int(_), Type::Int) => true,
            (Value::Bool(_), Type::Bool) => true,
            (Value::Bytes(_), Type::Bytes) => true,
            (Value::List(items), Type::List(element)) => {
                items.iter().all(|item| item.matches(element))
            }
            _ => false,
        }
    }
}

/// Declared external input to a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleDecl {
    pub name: String,
    pub ty: Type,
}

/// External facts supplied at evaluation time.
///
/// A `BTreeMap` is deliberate: it fixes iteration order and keeps evaluation
/// independent of host insertion order.
pub type OracleInput = BTreeMap<String, Value>;

/// A compiled, validated policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub(crate) name: String,
    pub(crate) oracles: Vec<OracleDecl>,
    pub(crate) code: Vec<Instr>,
}

impl Policy {
    /// Compile policy source text.
    ///
    /// The source is fully parsed and type-checked; the result is validated
    /// again before being returned.
    pub fn compile(source: &str) -> Result<Self, PolicyError> {
        if source.len() > MAX_SOURCE_LEN {
            return Err(PolicyError::SourceTooLong {
                len: source.len(),
                max: MAX_SOURCE_LEN,
            });
        }
        let program = parser::parse(source)?;
        bytecode::compile(program)
    }

    /// Decode and validate canonical bytecode.
    pub fn from_bytecode(bytes: &[u8]) -> Result<Self, PolicyError> {
        bytecode::decode(bytes)
    }

    /// Encode this policy into canonical bytecode.
    pub fn to_bytecode(&self) -> Vec<u8> {
        bytecode::encode(self)
    }

    /// Hash-locked policy id: `SHA-256("POLICY_V1:" ‖ bytecode)`.
    ///
    /// Reuses [`workstream_crypto::hash_policy`] so there is exactly one
    /// policy-hash definition in the workspace.
    pub fn id(&self) -> PolicyId {
        workstream_crypto::hash_policy(&self.to_bytecode())
    }

    /// Policy name (opaque metadata committed to by the id).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Declared oracle interface, sorted by name.
    pub fn oracles(&self) -> &[OracleDecl] {
        &self.oracles
    }

    /// Compiled instructions.
    pub fn code(&self) -> &[Instr] {
        &self.code
    }

    /// Evaluate the policy against its declared oracle inputs.
    ///
    /// Every declared oracle must be present and type-correct. Extra entries
    /// are ignored. Errors are not denials; callers choose a fail-closed
    /// policy if desired.
    pub fn evaluate(&self, oracles: &OracleInput) -> Result<bool, PolicyError> {
        interp::evaluate(self, oracles)
    }
}
