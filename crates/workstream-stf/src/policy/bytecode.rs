//! Canonical bytecode: compilation, encoding, decoding, and static validation.
//!
//! The container and instruction formats are specified in
//! `docs/design/policy-dsl.md`. All multi-byte integers are little-endian.

use std::collections::BTreeMap;

use super::ast::{BinOp, Expr, UnOp};
use super::error::{
    PolicyError, MAX_BYTES, MAX_INSTRUCTIONS, MAX_LIST, MAX_NAME_LEN, MAX_ORACLES, MAX_STACK,
};
use super::lexer::is_valid_ident;
use super::parser::Program;
use super::{OracleDecl, Policy, Type, MAX_IDENT_LEN};

const MAGIC: [u8; 4] = *b"WSPL";
const VERSION: u8 = 1;

const OP_HALT: u8 = 0x00;
const OP_PUSH_INT: u8 = 0x01;
const OP_PUSH_BOOL: u8 = 0x02;
const OP_PUSH_BYTES: u8 = 0x03;
const OP_LOAD_ORACLE: u8 = 0x04;
const OP_NOT: u8 = 0x05;
const OP_NEG: u8 = 0x06;
const OP_AND: u8 = 0x07;
const OP_OR: u8 = 0x08;
const OP_EQ: u8 = 0x09;
const OP_NE: u8 = 0x0A;
const OP_LT: u8 = 0x0B;
const OP_LE: u8 = 0x0C;
const OP_GT: u8 = 0x0D;
const OP_GE: u8 = 0x0E;
const OP_ADD: u8 = 0x0F;
const OP_SUB: u8 = 0x10;
const OP_MUL: u8 = 0x11;
const OP_IN: u8 = 0x12;
const OP_LIST: u8 = 0x13;
const OP_COUNT: u8 = 0x14;

/// A single stack-machine instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instr {
    Halt,
    PushInt(i64),
    PushBool(bool),
    PushBytes(Vec<u8>),
    LoadOracle(u16),
    Not,
    Neg,
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
    List(u16),
    Count,
}

/// Compile a parsed program into a validated [`Policy`].
pub(super) fn compile(mut program: Program) -> Result<Policy, PolicyError> {
    // Oracle declaration order is not semantic; sorting makes bytecode and
    // therefore the policy id independent of declaration order.
    program.oracles.sort_by(|a, b| a.name.cmp(&b.name));

    if program.oracles.len() > MAX_ORACLES {
        return Err(PolicyError::TooManyOracles {
            count: program.oracles.len(),
            max: MAX_ORACLES,
        });
    }

    let mut index = BTreeMap::new();
    for (position, oracle) in program.oracles.iter().enumerate() {
        index.insert(oracle.name.clone(), (position as u16, oracle.ty.clone()));
    }

    let mut code = Vec::new();
    let result_type = emit(&program.allow, &index, &mut code)?;
    if result_type != Type::Bool {
        return Err(PolicyError::NonBoolResult {
            found: result_type.to_string(),
        });
    }
    code.push(Instr::Halt);

    if code.len() > MAX_INSTRUCTIONS {
        return Err(PolicyError::TooManyInstructions {
            count: code.len(),
            max: MAX_INSTRUCTIONS,
        });
    }

    let policy = Policy {
        name: program.name,
        oracles: program.oracles,
        code,
    };
    validate(&policy)?;
    Ok(policy)
}

type OracleIndex = BTreeMap<String, (u16, Type)>;

/// Work item for the iterative (post-order) emitter.
///
/// The emitter is deliberately non-recursive so a long left-associative chain
/// (`a && b && c && ...`) cannot exhaust the native stack. The parser caps the
/// number of nodes, and this loop uses an explicit heap stack.
enum Task<'a> {
    Visit(&'a Expr),
    Unary(UnOp),
    Binary(BinOp),
    List(usize),
    Count,
}

fn emit(expr: &Expr, oracles: &OracleIndex, code: &mut Vec<Instr>) -> Result<Type, PolicyError> {
    let mut tasks = vec![Task::Visit(expr)];
    let mut types: Vec<Type> = Vec::new();

    while let Some(task) = tasks.pop() {
        match task {
            Task::Visit(expr) => match expr {
                Expr::Int(value) => {
                    code.push(Instr::PushInt(*value));
                    types.push(Type::Int);
                }
                Expr::Bool(value) => {
                    code.push(Instr::PushBool(*value));
                    types.push(Type::Bool);
                }
                Expr::Bytes(value) => {
                    if value.len() > MAX_BYTES {
                        return Err(PolicyError::BytesTooLong {
                            len: value.len(),
                            max: MAX_BYTES,
                        });
                    }
                    code.push(Instr::PushBytes(value.clone()));
                    types.push(Type::Bytes);
                }
                Expr::Oracle(name) => {
                    let (index, ty) = oracles
                        .get(name)
                        .ok_or_else(|| PolicyError::UndeclaredOracle { name: name.clone() })?;
                    code.push(Instr::LoadOracle(*index));
                    types.push(ty.clone());
                }
                Expr::List(items) => {
                    if items.is_empty() {
                        return Err(PolicyError::EmptyList);
                    }
                    if items.len() > MAX_LIST {
                        return Err(PolicyError::ListTooLong {
                            count: items.len(),
                            max: MAX_LIST,
                        });
                    }
                    tasks.push(Task::List(items.len()));
                    for item in items.iter().rev() {
                        tasks.push(Task::Visit(item));
                    }
                }
                Expr::Unary(op, inner) => {
                    tasks.push(Task::Unary(*op));
                    tasks.push(Task::Visit(inner));
                }
                Expr::Binary(op, left, right) => {
                    tasks.push(Task::Binary(*op));
                    tasks.push(Task::Visit(right));
                    tasks.push(Task::Visit(left));
                }
                Expr::Count(inner) => {
                    tasks.push(Task::Count);
                    tasks.push(Task::Visit(inner));
                }
            },
            Task::Unary(op) => {
                let operand = types
                    .pop()
                    .ok_or(PolicyError::Corrupt("missing unary operand type"))?;
                match op {
                    UnOp::Not => {
                        expect_type(operand, Type::Bool)?;
                        code.push(Instr::Not);
                        types.push(Type::Bool);
                    }
                    UnOp::Neg => {
                        expect_type(operand, Type::Int)?;
                        code.push(Instr::Neg);
                        types.push(Type::Int);
                    }
                }
            }
            Task::Binary(op) => {
                let right = types
                    .pop()
                    .ok_or(PolicyError::Corrupt("missing right operand type"))?;
                let left = types
                    .pop()
                    .ok_or(PolicyError::Corrupt("missing left operand type"))?;
                let result = finish_binary(op, left, right, code)?;
                types.push(result);
            }
            Task::List(count) => {
                if types.len() < count {
                    return Err(PolicyError::Corrupt("missing list element types"));
                }
                let start = types.len() - count;
                let element = types[start].clone();
                if !element.is_scalar() || types[start..].iter().any(|ty| ty != &element) {
                    return Err(PolicyError::TypeMismatch {
                        expected: element.to_string(),
                        found: "mixed or non-scalar list elements".to_string(),
                    });
                }
                types.truncate(start);
                code.push(Instr::List(count as u16));
                types.push(Type::List(Box::new(element)));
            }
            Task::Count => {
                let operand = types
                    .pop()
                    .ok_or(PolicyError::Corrupt("missing count operand type"))?;
                expect_type(operand, Type::List(Box::new(Type::Bool)))?;
                code.push(Instr::Count);
                types.push(Type::Int);
            }
        }
    }

    match types.len() {
        1 => types
            .pop()
            .ok_or(PolicyError::Corrupt("missing result type")),
        0 => Err(PolicyError::Corrupt("expression produced no type")),
        _ => Err(PolicyError::Corrupt("unbalanced expression types")),
    }
}

fn finish_binary(
    op: BinOp,
    left_type: Type,
    right_type: Type,
    code: &mut Vec<Instr>,
) -> Result<Type, PolicyError> {
    match op {
        BinOp::And | BinOp::Or => {
            expect_type(left_type, Type::Bool)?;
            expect_type(right_type, Type::Bool)?;
            code.push(if op == BinOp::And {
                Instr::And
            } else {
                Instr::Or
            });
            Ok(Type::Bool)
        }
        BinOp::Eq | BinOp::Ne => {
            if !left_type.is_scalar() || !right_type.is_scalar() {
                return Err(PolicyError::TypeMismatch {
                    expected: "scalar operands".to_string(),
                    found: format!("{left_type} and {right_type}"),
                });
            }
            if left_type != right_type {
                return Err(PolicyError::TypeMismatch {
                    expected: left_type.to_string(),
                    found: right_type.to_string(),
                });
            }
            code.push(if op == BinOp::Eq {
                Instr::Eq
            } else {
                Instr::Ne
            });
            Ok(Type::Bool)
        }
        BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
            expect_type(left_type, Type::Int)?;
            expect_type(right_type, Type::Int)?;
            code.push(match op {
                BinOp::Lt => Instr::Lt,
                BinOp::Le => Instr::Le,
                BinOp::Gt => Instr::Gt,
                _ => Instr::Ge,
            });
            Ok(Type::Bool)
        }
        BinOp::Add | BinOp::Sub | BinOp::Mul => {
            expect_type(left_type, Type::Int)?;
            expect_type(right_type, Type::Int)?;
            code.push(match op {
                BinOp::Add => Instr::Add,
                BinOp::Sub => Instr::Sub,
                _ => Instr::Mul,
            });
            Ok(Type::Int)
        }
        BinOp::In => {
            if !left_type.is_scalar() {
                return Err(PolicyError::TypeMismatch {
                    expected: "scalar operand".to_string(),
                    found: left_type.to_string(),
                });
            }
            let element_type = match right_type {
                Type::List(element) => *element,
                other => {
                    return Err(PolicyError::TypeMismatch {
                        expected: "list".to_string(),
                        found: other.to_string(),
                    })
                }
            };
            if element_type != left_type {
                return Err(PolicyError::TypeMismatch {
                    expected: element_type.to_string(),
                    found: left_type.to_string(),
                });
            }
            code.push(Instr::In);
            Ok(Type::Bool)
        }
    }
}

fn expect_type(actual: Type, expected: Type) -> Result<(), PolicyError> {
    if actual == expected {
        Ok(())
    } else {
        Err(PolicyError::TypeMismatch {
            expected: expected.to_string(),
            found: actual.to_string(),
        })
    }
}

/// Encode a validated policy into canonical bytecode.
pub(super) fn encode(policy: &Policy) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);

    let name = policy.name.as_bytes();
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name);

    out.extend_from_slice(&(policy.oracles.len() as u16).to_le_bytes());
    for oracle in &policy.oracles {
        let oracle_name = oracle.name.as_bytes();
        out.extend_from_slice(&(oracle_name.len() as u16).to_le_bytes());
        out.extend_from_slice(oracle_name);
        out.push(oracle.ty.tag());
    }

    out.extend_from_slice(&(policy.code.len() as u16).to_le_bytes());
    for instr in &policy.code {
        encode_instr(instr, &mut out);
    }
    out
}

fn encode_instr(instr: &Instr, out: &mut Vec<u8>) {
    match instr {
        Instr::Halt => out.push(OP_HALT),
        Instr::PushInt(value) => {
            out.push(OP_PUSH_INT);
            out.extend_from_slice(&value.to_le_bytes());
        }
        Instr::PushBool(value) => {
            out.push(OP_PUSH_BOOL);
            out.push(u8::from(*value));
        }
        Instr::PushBytes(value) => {
            out.push(OP_PUSH_BYTES);
            out.push(value.len() as u8);
            out.extend_from_slice(value);
        }
        Instr::LoadOracle(index) => {
            out.push(OP_LOAD_ORACLE);
            out.extend_from_slice(&index.to_le_bytes());
        }
        Instr::Not => out.push(OP_NOT),
        Instr::Neg => out.push(OP_NEG),
        Instr::And => out.push(OP_AND),
        Instr::Or => out.push(OP_OR),
        Instr::Eq => out.push(OP_EQ),
        Instr::Ne => out.push(OP_NE),
        Instr::Lt => out.push(OP_LT),
        Instr::Le => out.push(OP_LE),
        Instr::Gt => out.push(OP_GT),
        Instr::Ge => out.push(OP_GE),
        Instr::Add => out.push(OP_ADD),
        Instr::Sub => out.push(OP_SUB),
        Instr::Mul => out.push(OP_MUL),
        Instr::In => out.push(OP_IN),
        Instr::List(count) => {
            out.push(OP_LIST);
            out.extend_from_slice(&count.to_le_bytes());
        }
        Instr::Count => out.push(OP_COUNT),
    }
}

/// Decode and validate canonical bytecode.
pub(super) fn decode(bytes: &[u8]) -> Result<Policy, PolicyError> {
    let mut reader = Reader::new(bytes);

    if reader.take(4, "magic")? != MAGIC.as_slice() {
        return Err(PolicyError::BadMagic);
    }
    let version = reader.u8("version")?;
    if version != VERSION {
        return Err(PolicyError::UnsupportedVersion { version });
    }

    let name_len = reader.u16("name length")? as usize;
    if name_len > MAX_NAME_LEN {
        return Err(PolicyError::NameTooLong {
            len: name_len,
            max: MAX_NAME_LEN,
        });
    }
    let name = std::str::from_utf8(reader.take(name_len, "policy name")?)
        .map_err(|e| PolicyError::Utf8(e.to_string()))?
        .to_string();

    let oracle_count = reader.u16("oracle count")? as usize;
    if oracle_count > MAX_ORACLES {
        return Err(PolicyError::TooManyOracles {
            count: oracle_count,
            max: MAX_ORACLES,
        });
    }

    let mut oracles = Vec::with_capacity(oracle_count);
    let mut previous: Option<String> = None;
    for _ in 0..oracle_count {
        let oracle_len = reader.u16("oracle name length")? as usize;
        if oracle_len == 0 || oracle_len > MAX_IDENT_LEN {
            return Err(PolicyError::Corrupt("oracle name length out of range"));
        }
        let oracle_name = std::str::from_utf8(reader.take(oracle_len, "oracle name")?)
            .map_err(|e| PolicyError::Utf8(e.to_string()))?
            .to_string();
        if !is_valid_ident(&oracle_name) {
            return Err(PolicyError::Corrupt("invalid oracle identifier"));
        }
        if let Some(prev) = &previous {
            if prev >= &oracle_name {
                return Err(PolicyError::UnsortedOracles);
            }
        }
        previous = Some(oracle_name.clone());

        let tag = reader.u8("oracle type")?;
        let ty = Type::from_tag(tag)?;
        oracles.push(OracleDecl {
            name: oracle_name,
            ty,
        });
    }

    let code_len = reader.u16("instruction count")? as usize;
    if code_len > MAX_INSTRUCTIONS {
        return Err(PolicyError::TooManyInstructions {
            count: code_len,
            max: MAX_INSTRUCTIONS,
        });
    }

    let mut code = Vec::with_capacity(code_len);
    for index in 0..code_len {
        let opcode = reader.u8("opcode")?;
        let instr = match opcode {
            OP_HALT => Instr::Halt,
            OP_PUSH_INT => Instr::PushInt(reader.i64("integer operand")?),
            OP_PUSH_BOOL => match reader.u8("boolean operand")? {
                0 => Instr::PushBool(false),
                1 => Instr::PushBool(true),
                _ => return Err(PolicyError::Corrupt("boolean operand is not 0 or 1")),
            },
            OP_PUSH_BYTES => {
                let len = reader.u8("bytes length")? as usize;
                if len > MAX_BYTES {
                    return Err(PolicyError::BytesTooLong {
                        len,
                        max: MAX_BYTES,
                    });
                }
                Instr::PushBytes(reader.take(len, "bytes operand")?.to_vec())
            }
            OP_LOAD_ORACLE => Instr::LoadOracle(reader.u16("oracle index")?),
            OP_NOT => Instr::Not,
            OP_NEG => Instr::Neg,
            OP_AND => Instr::And,
            OP_OR => Instr::Or,
            OP_EQ => Instr::Eq,
            OP_NE => Instr::Ne,
            OP_LT => Instr::Lt,
            OP_LE => Instr::Le,
            OP_GT => Instr::Gt,
            OP_GE => Instr::Ge,
            OP_ADD => Instr::Add,
            OP_SUB => Instr::Sub,
            OP_MUL => Instr::Mul,
            OP_IN => Instr::In,
            OP_LIST => Instr::List(reader.u16("list length")?),
            OP_COUNT => Instr::Count,
            _ => return Err(PolicyError::InvalidOpcode { opcode, index }),
        };
        code.push(instr);
    }

    if reader.remaining() != 0 {
        return Err(PolicyError::TrailingBytes);
    }

    let policy = Policy {
        name,
        oracles,
        code,
    };
    validate(&policy)?;
    Ok(policy)
}

/// Validate structural limits and run a typed stack simulation.
pub(super) fn validate(policy: &Policy) -> Result<(), PolicyError> {
    if policy.name.len() > MAX_NAME_LEN {
        return Err(PolicyError::NameTooLong {
            len: policy.name.len(),
            max: MAX_NAME_LEN,
        });
    }
    if policy.oracles.len() > MAX_ORACLES {
        return Err(PolicyError::TooManyOracles {
            count: policy.oracles.len(),
            max: MAX_ORACLES,
        });
    }
    if policy.code.len() > MAX_INSTRUCTIONS {
        return Err(PolicyError::TooManyInstructions {
            count: policy.code.len(),
            max: MAX_INSTRUCTIONS,
        });
    }
    if policy.code.is_empty() {
        return Err(PolicyError::Corrupt("empty program"));
    }
    if !matches!(policy.code.last(), Some(Instr::Halt)) {
        return Err(PolicyError::Corrupt("program does not end with HALT"));
    }

    let mut stack: Vec<Type> = Vec::new();
    for (index, instr) in policy.code.iter().enumerate() {
        match instr {
            Instr::Halt => {
                if index + 1 != policy.code.len() {
                    return Err(PolicyError::Corrupt("HALT before end of program"));
                }
                if stack.len() != 1 {
                    return Err(PolicyError::StackNotEmpty { count: stack.len() });
                }
                let result = stack
                    .pop()
                    .ok_or(PolicyError::Corrupt("validated stack is empty"))?;
                if result != Type::Bool {
                    return Err(PolicyError::NonBoolResult {
                        found: result.to_string(),
                    });
                }
            }
            Instr::PushInt(_) => stack.push(Type::Int),
            Instr::PushBool(_) => stack.push(Type::Bool),
            Instr::PushBytes(value) => {
                if value.len() > MAX_BYTES {
                    return Err(PolicyError::BytesTooLong {
                        len: value.len(),
                        max: MAX_BYTES,
                    });
                }
                stack.push(Type::Bytes);
            }
            Instr::LoadOracle(index) => {
                let oracle = policy
                    .oracles
                    .get(*index as usize)
                    .ok_or(PolicyError::Corrupt("oracle index out of range"))?;
                stack.push(oracle.ty.clone());
            }
            Instr::Not => {
                pop_expect(&mut stack, Type::Bool, index)?;
                stack.push(Type::Bool);
            }
            Instr::Neg => {
                pop_expect(&mut stack, Type::Int, index)?;
                stack.push(Type::Int);
            }
            Instr::And | Instr::Or => {
                pop_expect(&mut stack, Type::Bool, index)?;
                pop_expect(&mut stack, Type::Bool, index)?;
                stack.push(Type::Bool);
            }
            Instr::Eq | Instr::Ne => {
                let right = pop(&mut stack, index)?;
                let left = pop(&mut stack, index)?;
                if !left.is_scalar() || !right.is_scalar() || left != right {
                    return Err(PolicyError::TypeMismatch {
                        expected: left.to_string(),
                        found: right.to_string(),
                    });
                }
                stack.push(Type::Bool);
            }
            Instr::Lt | Instr::Le | Instr::Gt | Instr::Ge => {
                pop_expect(&mut stack, Type::Int, index)?;
                pop_expect(&mut stack, Type::Int, index)?;
                stack.push(Type::Bool);
            }
            Instr::Add | Instr::Sub | Instr::Mul => {
                pop_expect(&mut stack, Type::Int, index)?;
                pop_expect(&mut stack, Type::Int, index)?;
                stack.push(Type::Int);
            }
            Instr::In => {
                let list_type = pop(&mut stack, index)?;
                let value_type = pop(&mut stack, index)?;
                let element_type = match list_type {
                    Type::List(element) => *element,
                    other => {
                        return Err(PolicyError::TypeMismatch {
                            expected: "list".to_string(),
                            found: other.to_string(),
                        })
                    }
                };
                if value_type != element_type || !value_type.is_scalar() {
                    return Err(PolicyError::TypeMismatch {
                        expected: element_type.to_string(),
                        found: value_type.to_string(),
                    });
                }
                stack.push(Type::Bool);
            }
            Instr::List(count) => {
                let count = *count as usize;
                if count == 0 || count > MAX_LIST {
                    return Err(PolicyError::Corrupt("list count out of range"));
                }
                if stack.len() < count {
                    return Err(PolicyError::StackUnderflow { index });
                }
                let start = stack.len() - count;
                let element = stack[start].clone();
                if !element.is_scalar() || stack[start..].iter().any(|ty| ty != &element) {
                    return Err(PolicyError::TypeMismatch {
                        expected: element.to_string(),
                        found: "mixed or non-scalar list elements".to_string(),
                    });
                }
                stack.truncate(start);
                stack.push(Type::List(Box::new(element)));
            }
            Instr::Count => {
                let list_type = pop(&mut stack, index)?;
                if list_type != Type::List(Box::new(Type::Bool)) {
                    return Err(PolicyError::TypeMismatch {
                        expected: "list<bool>".to_string(),
                        found: list_type.to_string(),
                    });
                }
                stack.push(Type::Int);
            }
        }

        if stack.len() > MAX_STACK {
            return Err(PolicyError::StackLimit { max: MAX_STACK });
        }
    }

    Ok(())
}

fn pop(stack: &mut Vec<Type>, index: usize) -> Result<Type, PolicyError> {
    stack.pop().ok_or(PolicyError::StackUnderflow { index })
}

fn pop_expect(stack: &mut Vec<Type>, expected: Type, index: usize) -> Result<(), PolicyError> {
    let found = pop(stack, index)?;
    if found == expected {
        Ok(())
    } else {
        Err(PolicyError::TypeMismatch {
            expected: expected.to_string(),
            found: found.to_string(),
        })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, position: 0 }
    }

    fn take(&mut self, len: usize, context: &'static str) -> Result<&'a [u8], PolicyError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(PolicyError::Truncated { context })?;
        if end > self.bytes.len() {
            return Err(PolicyError::Truncated { context });
        }
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn u8(&mut self, context: &'static str) -> Result<u8, PolicyError> {
        Ok(self.take(1, context)?[0])
    }

    fn u16(&mut self, context: &'static str) -> Result<u16, PolicyError> {
        let bytes = self.take(2, context)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn i64(&mut self, context: &'static str) -> Result<i64, PolicyError> {
        let bytes = self.take(8, context)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Ok(i64::from_le_bytes(array))
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
}
