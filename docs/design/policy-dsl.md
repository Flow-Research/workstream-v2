# Policy DSL — Design Spike

Status: **proposed** (spike for #26, implementation in #27)
Owner: STF / policy
Scope: hash-locked, bounded, deterministic policy evaluation for the Workstream
STF. This document defines the surface grammar, bytecode, execution semantics,
validation rules, and test plan. It is the contract for
`crates/workstream-stf/src/policy/`.

---

## 1. Goals and non-goals

### Goals

1. **Total.** Every well-formed program returns `Ok(bool)` or a typed
   `PolicyError`; no input can panic, abort, or loop forever.
2. **Terminating by construction.** The language has no loops, recursion,
   jumps, function definitions, or unbounded data. Runtime work is bounded by a
   statically validated instruction count.
3. **Deterministic.** Only integer arithmetic, boolean logic, byte equality,
   and ordered `BTreeMap` lookups. No floats, wall clocks, randomness, network
   access, or hash-map iteration.
4. **Hash-lockable.** A policy is identified by the SHA-256 of its canonical
   bytecode, so a task/guide can commit to exact evaluation semantics.
5. **Explicit oracle surface.** External facts are declared by name and type.
   The interpreter refuses undeclared or mistyped inputs.
6. **Small and auditable.** A fixed instruction set, explicit opcodes, and a
   linear type check that a reviewer can verify by hand.

### Non-goals (v1)

- General-purpose computation, loops, user-defined functions, or recursion.
- Floating point, strings, or arbitrary-precision integers.
- Short-circuit evaluation (see §6.5).
- On-chain compilation (policies are compiled off-chain; the chain validates
  bytecode and hashes it).
- Defining *which* oracle values come from. Oracle production is an
  application concern; the DSL only consumes declared values.

---

## 2. Threat model

| Threat | Mitigation |
| --- | --- |
| Non-termination / gas griefing | No loops or jumps; `code.len() <= 4096`; runtime step cap equals instruction count. |
| Consensus drift | Integer-only, no floats/maps/iteration order; canonical encoding; evaluation depends only on `(bytecode, oracle input)`. |
| Panic in the STF | No indexing without bounds checks, no `unwrap` on untrusted data, checked arithmetic, explicit stack-underflow errors. |
| Oracle confusion | Oracle names are declared, sorted, index-bound at compile time, and type-checked at evaluation. |
| Policy substitution | Policy id is the SHA-256 of canonical bytecode, domain-separated (`WS:v1:policy:`). |
| Resource blow-up via inputs | Hard caps on source size, oracle count, list length, byte-string length, stack depth, and instructions. |
| Malformed bytecode | Decoder validates magic/version/lengths, re-runs the type checker, and rejects trailing bytes. |

---

## 3. Surface grammar

The textual form is for humans and off-chain tooling. Consensus operates on
bytecode only.

```ebnf
policy      = "policy", string, "{", oracle*, "allow", expr, "}" ;
oracle      = "oracle", ident, ":", type, ";" ;
type        = "int" | "bool" | "bytes" ;

expr        = or_expr ;
or_expr     = and_expr, { "||", and_expr } ;
and_expr    = cmp_expr, { "&&", cmp_expr } ;
cmp_expr    = add_expr,
              [ ( "==" | "!=" | "<" | "<=" | ">" | ">=" ), add_expr
              | "in", list ] ;
add_expr    = mul_expr, { ( "+" | "-" ), mul_expr } ;
mul_expr    = unary, { "*", unary } ;
unary       = ( "!" | "-" ), unary | primary ;
primary     = integer
            | "true" | "false"
            | bytes_literal
            | ident
            | "(", expr, ")"
            | list
            | "count", "(", expr, ")" ;
list        = "[", expr, { ",", expr }, "]" ;
```

### 3.1 Lexical rules

| Token | Rule |
| --- | --- |
| Whitespace | Space, tab, CR, LF. Ignored between tokens. |
| Comments | `//` to end of line. Ignored. |
| `ident` | `[A-Za-z_][A-Za-z0-9_]*`, max 64 bytes. Reserved words cannot be identifiers. |
| `integer` | Decimal digits only, magnitude ≤ `i64::MAX`. Negation is the unary `-` operator, so the literal range is symmetric: `[-(2^63−1), 2^63−1]`. |
| `bytes_literal` | `0x` followed by an even number of hex digits, 0–64 bytes. Example: `0xdeadbeef`. |
| `string` | Double-quoted, length ≤ 128 bytes, escapes `\"` and `\\` only. Used for the policy name. |
| Reserved | `policy`, `oracle`, `allow`, `int`, `bool`, `bytes`, `true`, `false`, `count`, `in`. |

### 3.2 Types

| Type | Runtime value | Notes |
| --- | --- | --- |
| `int` | `i64` | Checked arithmetic; overflow is an evaluation error. |
| `bool` | `bool` | Result of comparisons and boolean operators. |
| `bytes` | `Vec<u8>` (≤ 64) | Equality only; no ordering in v1. |
| `list<T>` | homogeneous, non-empty, ≤ 256 elements | Internal only: list literals, `in`, `count`. Cannot be an oracle type or the final result. |

The `allow` expression must have type `bool`. A policy that produces any other
type is rejected at compile time.

### 3.3 Example

```text
policy "task-eligibility" {
    // Facts supplied by the caller; the policy cannot read anything else.
    oracle reputation: int;
    oracle allowlisted: bool;
    oracle member_of: bytes;
    oracle project: bytes;

    allow allowlisted
       && reputation >= 50
       && member_of in [0x1111, 0x2222, 0x3333]
       && project == 0xabcdef;
}
```

A threshold rule:

```text
policy "two-of-three" {
    oracle a: bool;
    oracle b: bool;
    oracle c: bool;
    allow count([a, b, c]) >= 2;
}
```

---

## 4. Semantics

### 4.1 Evaluation model

A policy is a straight-line stack program. Compilation preserves source order:
left operand is emitted before right operand. Operators pop their inputs and
push a result. `HALT` returns the single boolean on the stack.

- `&&` and `||` are **eager** (no short-circuit); both operands are always
  evaluated before the operator. This keeps the instruction stream branch-free
  and the cost exactly `code.len()`.
- `==` / `!=` require both sides to have the same scalar type.
- `<`, `<=`, `>`, `>=` are defined for `int` only.
- `+`, `-`, `*` are defined for `int` only and use checked operations. Overflow
  is an error, never a wrap or panic.
- `in` requires the right side to be a list literal and the left side to have
  the list's element type.
- `count(list<bool>)` returns the number of `true` elements as an `int`.
- Lists are non-empty and homogeneous. Empty list literals are rejected
  because they have no inferable element type.

### 4.2 Oracles

An oracle is a named, typed external value. At evaluation:

1. Every declared oracle must be present in the input map.
2. Its value must match the declared type (`int`/`bool`/`bytes`).
3. Extra input entries are ignored so a host can pass a shared fact set; they
   are never observable by the policy.

Oracle declarations are semantically an unordered set. The compiler sorts them
by name and binds `LOAD_ORACLE` to the sorted index. Reordering declarations
therefore does not change the policy id.

### 4.3 Errors are values

Any evaluation failure is a typed `PolicyError`; it is not a denial. Callers
that need fail-closed behavior must map `Err(_)` to deny. No error path mutates
state.

---

## 5. Bytecode format

### 5.1 Container

All integers are little-endian. Lengths are fixed-width; there is no padding
and no optional field. Bytecode is immutable once compiled.

```text
offset  field
0       magic       4 bytes   "WSPL"
4       version     u8        currently 1
5       name_len    u16       length of UTF-8 policy name (≤ 128)
7       name        bytes
...     oracle_n    u16       number of oracles (≤ 64)
...     oracles     repeated, sorted strictly ascending by name:
                        name_len u16, name bytes, type u8 (0=int, 1=bool, 2=bytes)
...     code_len    u16       number of instructions (≤ 4096)
...     code        `code_len` encoded instructions
```

The encoding is canonical:

- exactly one representation of a given program;
- oracle names sorted and unique (decoder rejects duplicates/unsorted);
- minimal-length names/strings (no padding);
- trailing bytes rejected;
- policy id = `SHA-256("WS:v1:policy:" ‖ bytecode)`.

### 5.2 Instruction encoding

Every instruction is a one-byte opcode followed by fixed operands.

| Opcode | Name | Operands | Stack effect | Semantics |
| --- | --- | --- | --- | --- |
| `0x00` | `HALT` | — | `[bool] → []` | Return top of stack. Must be last. |
| `0x01` | `PUSH_INT` | `i64` (8) | `[] → [int]` | Push constant. |
| `0x02` | `PUSH_BOOL` | `u8` (0/1) | `[] → [bool]` | Push constant. |
| `0x03` | `PUSH_BYTES` | `len u8` + bytes (≤64) | `[] → [bytes]` | Push constant. |
| `0x04` | `LOAD_ORACLE` | `index u16` | `[] → [T]` | Push declared oracle `T`. |
| `0x05` | `NOT` | — | `[bool] → [bool]` | Logical negation. |
| `0x06` | `NEG` | — | `[int] → [int]` | Checked negation. |
| `0x07` | `AND` | — | `[bool,bool] → [bool]` | Eager conjunction. |
| `0x08` | `OR` | — | `[bool,bool] → [bool]` | Eager disjunction. |
| `0x09` | `EQ` | — | `[T,T] → [bool]` | Equality of same scalar type. |
| `0x0A` | `NE` | — | `[T,T] → [bool]` | Inequality of same scalar type. |
| `0x0B` | `LT` | — | `[int,int] → [bool]` | `a < b`. |
| `0x0C` | `LE` | — | `[int,int] → [bool]` | `a <= b`. |
| `0x0D` | `GT` | — | `[int,int] → [bool]` | `a > b`. |
| `0x0E` | `GE` | — | `[int,int] → [bool]` | `a >= b`. |
| `0x0F` | `ADD` | — | `[int,int] → [int]` | Checked `a + b`. |
| `0x10` | `SUB` | — | `[int,int] → [int]` | Checked `a - b`. |
| `0x11` | `MUL` | — | `[int,int] → [int]` | Checked `a * b`. |
| `0x12` | `IN` | — | `[T,list<T>] → [bool]` | Membership. |
| `0x13` | `LIST` | `n u16` (1..=256) | `[T×n] → [list<T>]` | Build a homogeneous list. |
| `0x14` | `COUNT` | — | `[list<bool>] → [int]` | Number of `true`. |

Opcodes are frozen. New instructions may only be appended and require a
version bump if their meaning changes.

### 5.3 Static validation (decode and compile)

Before a program can execute, the validator performs a single linear pass with
a typed stack:

1. Container checks: magic, version, UTF-8, lengths, no trailing bytes.
2. Oracle checks: count ≤ 64, names ≤ 64 bytes, sorted strictly, valid type
   tags, no duplicates.
3. Instruction checks: opcode known, operands in range, `HALT` exactly once and
   last, `code_len ≤ 4096`.
4. Stack simulation: no underflow at any instruction; `LIST(n)` leaves exactly
   `n` typed elements; both operands of every binary op have the required
   types; final stack is exactly `[bool]`.
5. Limits: stack depth ≤ 256, list length ≤ 256, byte literal ≤ 64 bytes.

A program that fails any check is rejected; it is never partially executed.
Because there are no jumps, the static stack simulation is exact.

---

## 6. Execution rules

### 6.1 Determinism

- Values are `Int(i64)`, `Bool(bool)`, `Bytes(Vec<u8>)`, `List(Vec<Value>)`.
- Only `BTreeMap` is used for oracle input; no hash-map iteration.
- No floating point, locale, time, environment, or I/O.
- The same `(bytecode, oracle input)` always yields the same result/error.

### 6.2 Bounds

| Bound | Value |
| --- | --- |
| Source text | 16 KiB |
| Policy name | 128 bytes |
| Oracle count | 64 |
| Oracle name | 64 bytes |
| Instructions per policy | 4096 |
| List length | 256 |
| Byte literal / bytes value | 64 bytes |
| Parser nesting depth | 128 |
| Operand stack depth | 256 |
| Runtime steps | `code.len()` (defensive hard stop at 4096) |

### 6.3 Arithmetic

`ADD`, `SUB`, `MUL`, and `NEG` use `checked_*`; overflow returns
`PolicyError::ArithmeticOverflow`. No division or modulo exists in v1, so
there is no divide-by-zero path.

### 6.4 Stack discipline

The runtime re-checks stack height and operand types even though the bytecode
validator proved them. This is defense in depth against decoder bugs; a
mismatch returns `PolicyError::StackUnderflow`/`TypeMismatch`, never panics.
On `HALT`, the stack must contain exactly one `Bool`.

### 6.5 Eager boolean operators

`&&` and `||` do not short-circuit. A policy author who needs conditional
evaluation of a potentially overflowing expression must restructure it with
comparisons; v1 intentionally omits branches to keep the verifier trivial. This
is documented behavior, not an optimization gap.

---

## 7. Error taxonomy

| Variant group | Examples | When |
| --- | --- | --- |
| Parse | `UnexpectedToken`, `UnexpectedEof`, `InvalidNumber`, `InvalidBytes`, `InvalidString`, `NestingTooDeep` | Off-chain compilation of invalid source. |
| Limit | `SourceTooLong`, `NameTooLong`, `TooManyOracles`, `TooManyInstructions`, `ListTooLong`, `BytesTooLong` | A declared bound is exceeded. |
| Name/type | `DuplicateOracle`, `UndeclaredOracle`, `UnknownFunction`, `EmptyList`, `TypeMismatch`, `NonBoolResult` | Static rejection. |
| Bytecode | `BadMagic`, `UnsupportedVersion`, `TrailingBytes`, `InvalidOpcode`, `CorruptBytecode`, `StackUnderflow`, `StackNotEmpty` | Decoding hostile or corrupted bytes. |
| Evaluation | `MissingOracle`, `OracleTypeMismatch`, `ArithmeticOverflow`, `TypeMismatch` | Runtime facts do not match the declared interface. |

Compilation and decoding both return `Result<Policy, PolicyError>`.
Evaluation returns `Result<bool, PolicyError>`.

---

## 8. Versioning and upgrade policy

- `version = 1` is the only accepted version in this milestone.
- Policy identity commits to the full bytecode, including version.
- Adding an opcode requires: append-only opcode assignment, a version bump,
  and a fork-gated interpreter selection. Existing policies keep their id and
  semantics.
- Changing any existing opcode meaning is forbidden; ship a new opcode and a
  new version instead.
- The host decides when to evaluate a policy. This spike does not wire
  `policy.compile` / `policy.approve` actions; that is a later integration
  step.

---

## 9. Security analysis

1. **Termination.** There are no control-flow instructions other than `HALT`.
   The program counter advances by exactly one instruction per step, bounded by
   `code_len ≤ 4096`, so evaluation terminates in at most 4096 steps.
2. **Totality.** All arithmetic is checked; all stack accesses are bounds
   checked; decoding validates lengths before allocation; list/bytes/oracle
   counts are capped. Recursive descent is guarded by `MAX_NESTING`.
3. **Determinism.** No iteration over unordered containers, no clock, no
   randomness, no floats, no string comparison (policy names are not part of
   evaluation), no environment access.
4. **Oracle isolation.** A policy can only read declared names. Missing and
   mistyped inputs are errors. Extra host facts are invisible.
5. **Hash locking.** A task/guide stores `PolicyId`; any mutation of source or
   bytecode changes the id. `compile` is performed off-chain; consensus
   validates bytecode and compares ids.
6. **No state effects.** Evaluation is pure. The STF decides what a boolean
   means; the interpreter cannot read or write chain state.

---

## 10. Test plan (#27)

### Compiler and parser

- Happy-path compile/evaluate for eligibility, allowlists, and thresholds.
- Every operator and precedence level, including `!`, unary `-`, `&&`, `||`,
  comparisons, arithmetic, `in`, `count`, parentheses.
- Comments/whitespace do not change the policy id.
- Oracle declaration reordering produces identical bytecode and id.
- Type errors: non-bool `allow`, mixed-type comparisons, ordered `bytes`,
  heterogeneous lists, empty lists, `count` on non-bool lists, undeclared
  oracle, unknown function.
- Parse errors: bad token, EOF, malformed string/hex, invalid identifier,
  reserved word as oracle, nesting overflow.
- Limit tests: oversize source/name/oracle/list/byte literal/instruction count.

### Bytecode

- `encode`/`decode` roundtrip preserves name, oracles, code, and id.
- Encoder output is deterministic across repeated compiles.
- Decoder rejects: bad magic, wrong version, truncated input, trailing bytes,
  unknown opcode, duplicate/unsorted oracle names, bad type tag, list count 0,
  oversized literal, stack underflow, non-bool final stack.
- Policy id is domain-separated and changes when any byte changes.

### Evaluation

- All operators produce expected values; boolean operators are eager.
- Checked arithmetic: `i64::MAX + 1`, `i64::MIN`-adjacent subtraction, `NEG`
  overflow, `MUL` overflow return `ArithmeticOverflow`.
- Missing oracle, mistyped oracle, and extra oracle handling.
- Byte and integer membership; threshold counting.
- Evaluation is repeatable and independent of oracle insertion order.

### Property tests (proptest)

- Arbitrary source strings: `compile` never panics, always returns `Ok`/`Err`.
- Any successfully compiled policy: `to_bytecode`/`from_bytecode` roundtrips,
  and two compiles yield the same id.
- Any decoded policy: evaluation with type-correct oracle inputs never panics
  and always terminates (bounded by a step counter).
- Mutating a byte of valid bytecode either fails validation or yields a
  program that still terminates.

### Integration follow-up

- When policy actions are wired, add an STF test that stores `PolicyId`,
  evaluates it during task screening/routing, and proves that an unknown id or
  a mismatched oracle set is rejected deterministically.

---

## 11. Reference examples

```text
// Minimal allow.
policy "always" { allow true; }
```

```text
// Byte allowlist + reputation threshold.
policy "worker-eligibility" {
    oracle worker: bytes;
    oracle reputation: int;
    oracle allowlisted: bool;
    allow allowlisted
       && reputation >= 100
       && worker in [
            0x1111111111111111111111111111111111111111111111111111111111111111,
            0x2222222222222222222222222222222222222222222222222222222222222222
          ];
}
```

```text
// Multi-sig style threshold over booleans.
policy "quorum" {
    oracle alice: bool;
    oracle bob: bool;
    oracle carol: bool;
    allow count([alice, bob, carol]) >= 2;
}
```

```text
// Arithmetic and nested lists.
policy "budget" {
    oracle base: int;
    oracle bonus: int;
    oracle approvals: int;
    oracle required: int;
    allow base + bonus * 2 >= required
       && approvals in [1, 2, 3];
}
```

---

## 12. Implementation layout (#27)

```text
crates/workstream-stf/src/policy/
├── mod.rs        // public API: Policy, Type, Value, OracleInput, PolicyId
├── error.rs      // PolicyError and Display/Error impl
├── lexer.rs      // tokens with source offsets
├── ast.rs        // expression tree
├── parser.rs     // recursive-descent parser + depth guard
├── bytecode.rs   // Instr/Op, canonical encode/decode, typed stack validation
└── interp.rs     // stack-machine evaluator with checked arithmetic
```

Public surface:

```rust
pub struct Policy { /* name, oracles, code */ }
pub enum Type { Int, Bool, Bytes, List(Box<Type>) }
pub enum Value { Int(i64), Bool(bool), Bytes(Vec<u8>), List(Vec<Value>) }
pub type OracleInput = std::collections::BTreeMap<String, Value>;

impl Policy {
    pub fn compile(source: &str) -> Result<Self, PolicyError>;
    pub fn from_bytecode(bytes: &[u8]) -> Result<Self, PolicyError>;
    pub fn to_bytecode(&self) -> Vec<u8>;
    pub fn id(&self) -> PolicyId;
    pub fn evaluate(&self, oracles: &OracleInput) -> Result<bool, PolicyError>;
}
```

---

## 13. Decisions and open questions

### Decided

- Expression language, not statement language; `allow <expr>` is the only
  outcome.
- Eager booleans; no branches.
- No list-typed oracles, no list-typed result.
- Oracle declarations are sorted for canonical bytecode.
- `PolicyId` commits to bytecode, not source text.
- Arithmetic is `i64` with checked overflow.

### Open (deferred, non-blocking for v1)

- Should `from_bytecode` preserve the exact source name or treat it as opaque
  metadata? (Chosen: opaque, part of the id.)
- Should extra oracle inputs be rejected in a stricter host mode? (Chosen:
  ignored for composability.)
- Future opcodes for short-circuit selection or field access, gated by a
  version bump.
- Wiring `policy.compile` / `policy.approve` and storing policies in state is a
  follow-up integration issue.
