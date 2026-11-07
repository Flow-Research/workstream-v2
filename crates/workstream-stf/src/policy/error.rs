//! Typed errors for compilation, decoding, and evaluation.
//!
//! Every failure mode is represented here; no policy path panics or aborts.

use thiserror::Error;

/// Maximum policy source length accepted by the compiler.
pub const MAX_SOURCE_LEN: usize = 16 * 1024;
/// Maximum UTF-8 name length (policy names and oracle identifiers).
pub const MAX_NAME_LEN: usize = 128;
/// Maximum oracle count.
pub const MAX_ORACLES: usize = 64;
/// Maximum entries in an oracle input map (declared plus extra facts).
pub const MAX_ORACLE_INPUTS: usize = 1024;
/// Maximum instructions in a program (also the hard runtime step bound).
pub const MAX_INSTRUCTIONS: usize = 4096;
/// Maximum elements in a list literal.
pub const MAX_LIST: usize = 256;
/// Maximum bytes in a byte literal or byte value.
pub const MAX_BYTES: usize = 64;
/// Maximum parser recursion depth.
pub const MAX_NESTING: usize = 128;
/// Maximum operand stack depth.
///
/// Every instruction pushes at most one value, so `MAX_INSTRUCTIONS` also
/// bounds the operand stack. Keeping this equal to `MAX_INSTRUCTIONS` ensures
/// a maximum-length list literal is not rejected merely because other operands
/// are waiting (for example, `x in [..256..]` or a list nested inside another
/// expression).
pub const MAX_STACK: usize = MAX_INSTRUCTIONS;

/// Errors produced while compiling, decoding, or evaluating a policy.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    #[error("policy source is {len} bytes, maximum is {max}")]
    SourceTooLong { len: usize, max: usize },

    #[error("policy name is {len} bytes, maximum is {max}")]
    NameTooLong { len: usize, max: usize },

    #[error("identifier is {len} bytes, maximum is {max}")]
    IdentifierTooLong { len: usize, max: usize },

    #[error("nesting depth exceeds {max}")]
    NestingTooDeep { max: usize },

    #[error("unexpected token {found} at byte {offset}, expected {expected}")]
    UnexpectedToken {
        offset: usize,
        expected: String,
        found: String,
    },

    #[error("unexpected end of input, expected {expected}")]
    UnexpectedEof { expected: String },

    #[error("invalid integer literal at byte {offset}")]
    InvalidNumber { offset: usize },

    #[error("invalid byte literal at byte {offset}: {reason}")]
    InvalidBytes { offset: usize, reason: String },

    #[error("invalid string literal at byte {offset}: {reason}")]
    InvalidString { offset: usize, reason: String },

    #[error("invalid character {ch:?} at byte {offset}")]
    InvalidCharacter { offset: usize, ch: char },

    #[error("duplicate oracle name {name:?}")]
    DuplicateOracle { name: String },

    #[error("too many oracles: {count}, maximum is {max}")]
    TooManyOracles { count: usize, max: usize },

    #[error("too many instructions: {count}, maximum is {max}")]
    TooManyInstructions { count: usize, max: usize },

    #[error("list has {count} elements, maximum is {max}")]
    ListTooLong { count: usize, max: usize },

    #[error("empty list literals are not allowed")]
    EmptyList,

    #[error("byte value is {len} bytes, maximum is {max}")]
    BytesTooLong { len: usize, max: usize },

    #[error("undeclared oracle {name:?}")]
    UndeclaredOracle { name: String },

    #[error("unknown function {name:?}")]
    UnknownFunction { name: String },

    #[error("type mismatch: expected {expected}, found {found}")]
    TypeMismatch { expected: String, found: String },

    #[error("policy result must be bool, found {found}")]
    NonBoolResult { found: String },

    #[error("bad policy bytecode magic")]
    BadMagic,

    #[error("unsupported policy bytecode version {version}")]
    UnsupportedVersion { version: u8 },

    #[error("truncated policy bytecode: {context}")]
    Truncated { context: &'static str },

    #[error("trailing bytes after policy bytecode")]
    TrailingBytes,

    #[error("invalid policy opcode 0x{opcode:02x} at instruction {index}")]
    InvalidOpcode { opcode: u8, index: usize },

    #[error("corrupt policy bytecode: {0}")]
    Corrupt(&'static str),

    #[error("policy bytecode stack underflow at instruction {index}")]
    StackUnderflow { index: usize },

    #[error("policy operand stack exceeds {max} entries")]
    StackLimit { max: usize },

    #[error("policy bytecode leaves {count} values on the stack at HALT")]
    StackNotEmpty { count: usize },

    #[error("missing oracle {name:?}")]
    MissingOracle { name: String },

    #[error("oracle {name:?} expects {expected}, found {found}")]
    OracleTypeMismatch {
        name: String,
        expected: String,
        found: String,
    },

    #[error("oracle {name:?} byte value is {len} bytes, maximum is {max}")]
    OracleBytesTooLong {
        name: String,
        len: usize,
        max: usize,
    },

    #[error("oracle input has {count} entries, maximum is {max}")]
    TooManyInputs { count: usize, max: usize },

    #[error("integer overflow during policy evaluation")]
    ArithmeticOverflow,

    #[error("invalid UTF-8 in policy bytecode: {0}")]
    Utf8(String),

    #[error("policy bytecode oracle names are not strictly sorted")]
    UnsortedOracles,

    #[error("policy step limit exceeded")]
    StepLimit,
}
