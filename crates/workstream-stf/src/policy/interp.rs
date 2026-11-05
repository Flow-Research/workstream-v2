//! Bounded stack-machine evaluator.
//!
//! The bytecode validator proves stack safety and types ahead of time. The
//! interpreter re-checks both anyway, so a decoder bug can only produce a
//! `PolicyError`, never a panic. Execution has no loops: it walks the
//! instruction vector exactly once and stops at `HALT`.

use super::bytecode::Instr;
use super::error::{PolicyError, MAX_INSTRUCTIONS, MAX_LIST, MAX_STACK};
use super::{OracleInput, Policy, Value};

/// Evaluate a validated policy against its declared oracle inputs.
///
/// Returns the boolean result of `allow`. Missing or mistyped oracle values
/// are errors; the caller decides whether an error means deny (fail closed).
pub fn evaluate(policy: &Policy, oracles: &OracleInput) -> Result<bool, PolicyError> {
    // Validate the complete oracle interface up front. Extra inputs are
    // intentionally ignored so hosts can pass a shared fact set.
    for oracle in &policy.oracles {
        let value = oracles
            .get(&oracle.name)
            .ok_or_else(|| PolicyError::MissingOracle {
                name: oracle.name.clone(),
            })?;
        if !value.matches(&oracle.ty) {
            return Err(PolicyError::OracleTypeMismatch {
                name: oracle.name.clone(),
                expected: oracle.ty.to_string(),
                found: value.type_of().to_string(),
            });
        }
    }

    let mut stack: Vec<Value> = Vec::new();
    let mut steps = 0usize;

    for (index, instr) in policy.code.iter().enumerate() {
        steps += 1;
        if steps > MAX_INSTRUCTIONS {
            return Err(PolicyError::StepLimit);
        }

        match instr {
            Instr::Halt => {
                return match stack.pop() {
                    Some(Value::Bool(result)) if stack.is_empty() => Ok(result),
                    Some(Value::Bool(_)) => Err(PolicyError::StackNotEmpty {
                        count: stack.len() + 1,
                    }),
                    Some(other) => Err(PolicyError::NonBoolResult {
                        found: other.type_of().to_string(),
                    }),
                    None => Err(PolicyError::StackUnderflow { index }),
                };
            }
            Instr::PushInt(value) => stack.push(Value::Int(*value)),
            Instr::PushBool(value) => stack.push(Value::Bool(*value)),
            Instr::PushBytes(value) => stack.push(Value::Bytes(value.clone())),
            Instr::LoadOracle(index) => {
                let oracle = policy
                    .oracles
                    .get(*index as usize)
                    .ok_or(PolicyError::Corrupt("oracle index out of range"))?;
                let value =
                    oracles
                        .get(&oracle.name)
                        .ok_or_else(|| PolicyError::MissingOracle {
                            name: oracle.name.clone(),
                        })?;
                stack.push(value.clone());
            }
            Instr::Not => {
                let value = pop_bool(&mut stack, index)?;
                stack.push(Value::Bool(!value));
            }
            Instr::Neg => {
                let value = pop_int(&mut stack, index)?;
                let negated = value.checked_neg().ok_or(PolicyError::ArithmeticOverflow)?;
                stack.push(Value::Int(negated));
            }
            Instr::And => {
                let right = pop_bool(&mut stack, index)?;
                let left = pop_bool(&mut stack, index)?;
                stack.push(Value::Bool(left && right));
            }
            Instr::Or => {
                let right = pop_bool(&mut stack, index)?;
                let left = pop_bool(&mut stack, index)?;
                stack.push(Value::Bool(left || right));
            }
            Instr::Eq | Instr::Ne => {
                let right = pop(&mut stack, index)?;
                let left = pop(&mut stack, index)?;
                if !left.type_of().is_scalar()
                    || !right.type_of().is_scalar()
                    || left.type_of() != right.type_of()
                {
                    return Err(PolicyError::TypeMismatch {
                        expected: left.type_of().to_string(),
                        found: right.type_of().to_string(),
                    });
                }
                let equal = left == right;
                stack.push(Value::Bool(if *instr == Instr::Eq {
                    equal
                } else {
                    !equal
                }));
            }
            Instr::Lt | Instr::Le | Instr::Gt | Instr::Ge => {
                let right = pop_int(&mut stack, index)?;
                let left = pop_int(&mut stack, index)?;
                let result = match instr {
                    Instr::Lt => left < right,
                    Instr::Le => left <= right,
                    Instr::Gt => left > right,
                    _ => left >= right,
                };
                stack.push(Value::Bool(result));
            }
            Instr::Add | Instr::Sub | Instr::Mul => {
                let right = pop_int(&mut stack, index)?;
                let left = pop_int(&mut stack, index)?;
                let result = match instr {
                    Instr::Add => left.checked_add(right),
                    Instr::Sub => left.checked_sub(right),
                    _ => left.checked_mul(right),
                }
                .ok_or(PolicyError::ArithmeticOverflow)?;
                stack.push(Value::Int(result));
            }
            Instr::In => {
                let list = pop_list(&mut stack, index)?;
                let value = pop(&mut stack, index)?;
                if !value.type_of().is_scalar() {
                    return Err(PolicyError::TypeMismatch {
                        expected: "scalar operand".to_string(),
                        found: value.type_of().to_string(),
                    });
                }
                let found = list
                    .iter()
                    .any(|candidate| candidate.type_of() == value.type_of() && candidate == &value);
                stack.push(Value::Bool(found));
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
                let items = stack.split_off(start);
                if items.iter().any(|item| !item.type_of().is_scalar()) {
                    return Err(PolicyError::TypeMismatch {
                        expected: "scalar list element".to_string(),
                        found: "list".to_string(),
                    });
                }
                stack.push(Value::List(items));
            }
            Instr::Count => {
                let list = pop_list(&mut stack, index)?;
                let mut count = 0i64;
                for item in list {
                    match item {
                        Value::Bool(true) => count += 1,
                        Value::Bool(false) => {}
                        other => {
                            return Err(PolicyError::TypeMismatch {
                                expected: "bool list element".to_string(),
                                found: other.type_of().to_string(),
                            })
                        }
                    }
                }
                stack.push(Value::Int(count));
            }
        }

        if stack.len() > MAX_STACK {
            return Err(PolicyError::StackLimit { max: MAX_STACK });
        }
    }

    Err(PolicyError::Corrupt("program ended without HALT"))
}

fn pop(stack: &mut Vec<Value>, index: usize) -> Result<Value, PolicyError> {
    stack.pop().ok_or(PolicyError::StackUnderflow { index })
}

fn pop_int(stack: &mut Vec<Value>, index: usize) -> Result<i64, PolicyError> {
    match pop(stack, index)? {
        Value::Int(value) => Ok(value),
        other => Err(PolicyError::TypeMismatch {
            expected: "int".to_string(),
            found: other.type_of().to_string(),
        }),
    }
}

fn pop_bool(stack: &mut Vec<Value>, index: usize) -> Result<bool, PolicyError> {
    match pop(stack, index)? {
        Value::Bool(value) => Ok(value),
        other => Err(PolicyError::TypeMismatch {
            expected: "bool".to_string(),
            found: other.type_of().to_string(),
        }),
    }
}

fn pop_list(stack: &mut Vec<Value>, index: usize) -> Result<Vec<Value>, PolicyError> {
    match pop(stack, index)? {
        Value::List(items) => Ok(items),
        other => Err(PolicyError::TypeMismatch {
            expected: "list".to_string(),
            found: other.type_of().to_string(),
        }),
    }
}
