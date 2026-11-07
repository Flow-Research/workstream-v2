use super::*;
use proptest::prelude::*;
use workstream_core::hash::Hash;

fn policy(source: &str) -> Policy {
    Policy::compile(source).expect("policy compiles")
}

fn input(pairs: &[(&str, Value)]) -> OracleInput {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_string(), value.clone()))
        .collect()
}

fn eval(source: &str, pairs: &[(&str, Value)]) -> Result<bool, PolicyError> {
    policy(source).evaluate(&input(pairs))
}

const ELIGIBILITY: &str = r#"
policy "eligibility" {
    oracle reputation: int;
    oracle allowlisted: bool;
    oracle member: bytes;
    oracle project: bytes;
    allow allowlisted
       && reputation >= 50
       && member in [0x1111, 0x2222]
       && project == 0xabcd;
}
"#;

#[test]
fn compiles_and_evaluates_declared_oracles() {
    let allowed = eval(
        ELIGIBILITY,
        &[
            ("reputation", Value::Int(75)),
            ("allowlisted", Value::Bool(true)),
            ("member", Value::Bytes(vec![0x11, 0x11])),
            ("project", Value::Bytes(vec![0xab, 0xcd])),
        ],
    )
    .unwrap();
    assert!(allowed);

    let denied = eval(
        ELIGIBILITY,
        &[
            ("reputation", Value::Int(49)),
            ("allowlisted", Value::Bool(true)),
            ("member", Value::Bytes(vec![0x11, 0x11])),
            ("project", Value::Bytes(vec![0xab, 0xcd])),
        ],
    )
    .unwrap();
    assert!(!denied);

    // Declarations are canonicalized by name in the bytecode.
    let compiled = policy(ELIGIBILITY);
    let names: Vec<&str> = compiled
        .oracles()
        .iter()
        .map(|oracle| oracle.name.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["allowlisted", "member", "project", "reputation"]
    );
}

#[test]
fn all_operators_and_precedence() {
    let source = r#"
        policy "ops" {
            allow 1 + 2 * 3 == 7
               && 10 - 2 - 3 == 5
               && !false
               && (2 < 3) && (3 <= 3) && (4 > 3) && (4 >= 4)
               && (1 != 2) && (true || false)
               && -5 + 8 == 3;
        }
    "#;
    assert!(eval(source, &[]).unwrap());
}

#[test]
fn threshold_counting_and_membership() {
    let source = r#"
        policy "quorum" {
            oracle a: bool;
            oracle b: bool;
            oracle c: bool;
            allow count([a, b, c]) >= 2;
        }
    "#;
    let cases = [
        (true, false, false, false),
        (true, true, false, true),
        (true, false, true, true),
        (false, true, true, true),
        (true, true, true, true),
        (false, false, false, false),
    ];
    for (a, b, c, expected) in cases {
        let result = eval(
            source,
            &[
                ("a", Value::Bool(a)),
                ("b", Value::Bool(b)),
                ("c", Value::Bool(c)),
            ],
        )
        .unwrap();
        assert_eq!(result, expected, "a={a} b={b} c={c}");
    }
}

#[test]
fn policy_id_is_stable_and_domain_separated() {
    let first = policy(ELIGIBILITY);
    let second = policy(ELIGIBILITY);
    assert_eq!(first.id(), second.id());

    // Formatting and comments are not semantic.
    let reformatted = r#"policy "eligibility"{
        // same declarations, different order
        oracle project:bytes; oracle member:bytes;
        oracle allowlisted:bool; oracle reputation:int;
        allow allowlisted&&(reputation>=50)&&member in[0x1111,0x2222]&&project==0xabcd;
    }"#;
    assert_eq!(first.id(), policy(reformatted).id());

    // A semantic change must change the id.
    let changed = ELIGIBILITY.replace("reputation >= 50", "reputation >= 51");
    assert_ne!(first.id(), policy(&changed).id());

    // Domain separation: the id is not the bare bytecode hash, and it reuses
    // the single workspace policy-hash helper.
    assert_ne!(first.id(), Hash::sha256(&first.to_bytecode()));
    assert_eq!(
        first.id(),
        workstream_crypto::hash_policy(&first.to_bytecode())
    );
}

#[test]
fn allow_terminator_is_required() {
    assert!(Policy::compile(r#"policy "p" { allow true }"#).is_err());
    assert!(Policy::compile(r#"policy "p" { allow true; }"#).is_ok());
}

#[test]
fn bytecode_roundtrip_preserves_semantics() {
    let original = policy(ELIGIBILITY);
    let encoded = original.to_bytecode();
    let decoded = Policy::from_bytecode(&encoded).unwrap();

    assert_eq!(original, decoded);
    assert_eq!(original.id(), decoded.id());
    assert_eq!(encoded, decoded.to_bytecode());

    let facts = input(&[
        ("reputation", Value::Int(75)),
        ("allowlisted", Value::Bool(true)),
        ("member", Value::Bytes(vec![0x22, 0x22])),
        ("project", Value::Bytes(vec![0xab, 0xcd])),
    ]);
    assert_eq!(
        original.evaluate(&facts).unwrap(),
        decoded.evaluate(&facts).unwrap()
    );
}

#[test]
fn missing_and_mistyped_oracles_are_errors() {
    let source = r#"policy "p" { oracle value: int; allow value > 0; }"#;
    let policy = policy(source);

    let missing = policy.evaluate(&OracleInput::new()).unwrap_err();
    assert!(matches!(
        missing,
        PolicyError::MissingOracle { ref name } if name == "value"
    ));

    let mistyped = policy
        .evaluate(&input(&[("value", Value::Bool(true))]))
        .unwrap_err();
    assert!(matches!(
        mistyped,
        PolicyError::OracleTypeMismatch { ref name, .. } if name == "value"
    ));

    // Extra facts are invisible to the policy.
    assert!(policy
        .evaluate(&input(&[
            ("value", Value::Int(1)),
            ("unrelated", Value::Bytes(vec![1, 2, 3])),
        ]))
        .unwrap());
}

#[test]
fn oracle_input_bounds_are_enforced() {
    let bytes_policy = policy(r#"policy "p" { oracle blob: bytes; allow blob == 0x00; }"#);
    let oversized = bytes_policy
        .evaluate(&input(&[("blob", Value::Bytes(vec![0; MAX_BYTES + 1]))]))
        .unwrap_err();
    assert!(matches!(
        oversized,
        PolicyError::OracleBytesTooLong { ref name, len, max }
            if name == "blob" && len == MAX_BYTES + 1 && max == MAX_BYTES
    ));

    let trivial = policy(r#"policy "p" { allow true; }"#);
    let too_many: OracleInput = (0..=MAX_ORACLE_INPUTS)
        .map(|index| (format!("extra{index}"), Value::Int(0)))
        .collect();
    assert_eq!(
        trivial.evaluate(&too_many).unwrap_err(),
        PolicyError::TooManyInputs {
            count: MAX_ORACLE_INPUTS + 1,
            max: MAX_ORACLE_INPUTS,
        }
    );
}

#[test]
fn nested_lists_are_rejected() {
    let cases = [
        r#"policy "p" { allow [true] in [[true]]; }"#,
        r#"policy "p" { allow [[1], [2]] == [[1], [2]]; }"#,
        r#"policy "p" { allow count([[true]]); }"#,
    ];
    for source in cases {
        assert!(
            matches!(
                Policy::compile(source),
                Err(PolicyError::TypeMismatch { .. })
            ),
            "expected TypeMismatch for {source}"
        );
    }
}

#[test]
fn equality_and_ordering_are_type_checked() {
    let cases = [
        r#"policy "p" { allow 1; }"#,
        r#"policy "p" { allow 1 + true; }"#,
        r#"policy "p" { allow 0x01 < 0x02; }"#,
        r#"policy "p" { allow [1, true] == [1]; }"#,
        r#"policy "p" { allow 1 in [true]; }"#,
        r#"policy "p" { allow count([1, 2]) > 0; }"#,
        r#"policy "p" { allow missing; }"#,
        r#"policy "p" { allow []; }"#,
        r#"policy "p" { allow 1 = 1; }"#,
        r#"policy "p" { allow count([true]); }"#,
    ];
    for source in cases {
        assert!(
            Policy::compile(source).is_err(),
            "expected compile error for {source}"
        );
    }
}

#[test]
fn arithmetic_overflow_is_an_error_not_a_panic() {
    let cases = [
        r#"policy "p" { allow 9223372036854775807 + 1 > 0; }"#,
        r#"policy "p" { allow (0 - 9223372036854775807) - 2 > 0; }"#,
        r#"policy "p" { allow 9223372036854775807 * 2 > 0; }"#,
        r#"policy "p" { allow -((0 - 9223372036854775807) - 1) > 0; }"#,
    ];
    for source in cases {
        let err = eval(source, &[]).unwrap_err();
        assert_eq!(err, PolicyError::ArithmeticOverflow, "source: {source}");
    }
}

#[test]
fn boolean_operators_are_eager() {
    // No short-circuiting: the right operand still overflows.
    let err = eval(
        r#"policy "p" { allow false && (9223372036854775807 + 1 > 0); }"#,
        &[],
    )
    .unwrap_err();
    assert_eq!(err, PolicyError::ArithmeticOverflow);
}

#[test]
fn parser_limits_are_enforced() {
    let oversized = " ".repeat(MAX_SOURCE_LEN + 1);
    assert!(matches!(
        Policy::compile(&oversized),
        Err(PolicyError::SourceTooLong { .. })
    ));

    let long_bytes = format!("policy \"p\" {{ allow 0x{} == 0x00; }}", "00".repeat(65));
    assert!(matches!(
        Policy::compile(&long_bytes),
        Err(PolicyError::BytesTooLong { .. })
    ));

    let mut list = String::from("policy \"p\" { allow 1 in [");
    for index in 0..=MAX_LIST {
        if index > 0 {
            list.push(',');
        }
        list.push('1');
    }
    list.push_str("]; }");
    assert!(matches!(
        Policy::compile(&list),
        Err(PolicyError::ListTooLong { .. })
    ));

    let nested = format!(
        "policy \"p\" {{ allow {}true{}; }}",
        "(".repeat(MAX_NESTING + 8),
        ")".repeat(MAX_NESTING + 8)
    );
    assert!(matches!(
        Policy::compile(&nested),
        Err(PolicyError::NestingTooDeep { .. })
    ));

    let mut many_oracles = String::from("policy \"p\" {");
    for index in 0..=MAX_ORACLES {
        many_oracles.push_str(&format!(" oracle o{index}: int;"));
    }
    many_oracles.push_str(" allow true; }");
    assert!(matches!(
        Policy::compile(&many_oracles),
        Err(PolicyError::TooManyOracles { .. })
    ));

    let duplicate = r#"policy "p" { oracle a: int; oracle a: bool; allow true; }"#;
    assert!(matches!(
        Policy::compile(duplicate),
        Err(PolicyError::DuplicateOracle { .. })
    ));
}

#[test]
fn decode_rejects_corrupt_bytecode() {
    let valid = policy(ELIGIBILITY).to_bytecode();

    let mut bad_magic = valid.clone();
    bad_magic[0] = b'X';
    assert_eq!(
        Policy::from_bytecode(&bad_magic).unwrap_err(),
        PolicyError::BadMagic
    );

    let mut bad_version = valid.clone();
    bad_version[4] = 2;
    assert_eq!(
        Policy::from_bytecode(&bad_version).unwrap_err(),
        PolicyError::UnsupportedVersion { version: 2 }
    );

    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(
        Policy::from_bytecode(&trailing).unwrap_err(),
        PolicyError::TrailingBytes
    );

    let mut truncated = valid.clone();
    truncated.pop();
    assert!(matches!(
        Policy::from_bytecode(&truncated),
        Err(PolicyError::Truncated { .. })
    ));

    let mut bad_opcode = valid;
    let offset = code_offset(&bad_opcode);
    bad_opcode[offset] = 0xFF;
    assert!(matches!(
        Policy::from_bytecode(&bad_opcode),
        Err(PolicyError::InvalidOpcode { opcode: 0xFF, .. })
    ));
}

#[test]
fn decode_rejects_unsorted_oracles() {
    let mut bytes =
        policy(r#"policy "p" { oracle aa: int; oracle bb: int; allow aa == bb; }"#).to_bytecode();

    let first = first_oracle_name_offset(&bytes);
    let name_len = u16::from_le_bytes([bytes[first - 2], bytes[first - 1]]) as usize;
    let second = first + name_len + 1 + 2;
    for index in 0..name_len {
        bytes.swap(first + index, second + index);
    }

    assert_eq!(
        Policy::from_bytecode(&bytes).unwrap_err(),
        PolicyError::UnsortedOracles
    );
}

#[test]
fn oracle_insertion_order_does_not_matter() {
    let source = r#"policy "p" { oracle a: int; oracle b: int; allow a == b; }"#;
    let policy = policy(source);

    let first = input(&[("a", Value::Int(7)), ("b", Value::Int(7))]);
    let second = input(&[("b", Value::Int(7)), ("a", Value::Int(7))]);
    assert_eq!(
        policy.evaluate(&first).unwrap(),
        policy.evaluate(&second).unwrap()
    );
}

#[test]
fn long_associative_chain_compiles_and_evaluates() {
    // A left-leaning chain does not recurse in the parser or the emitter, so
    // it must compile and evaluate without touching the native stack depth.
    let terms = 1000;
    let mut source = String::from("policy \"chain\" { allow true");
    for _ in 0..terms {
        source.push_str(" && true");
    }
    source.push_str("; }");

    let compiled = policy(&source);
    assert!(compiled.evaluate(&OracleInput::new()).unwrap());
    // One push per `true` plus one `AND` per operand, then `HALT`.
    assert_eq!(compiled.code().len(), 1 + terms * 2 + 1);
}

#[test]
fn ast_node_budget_is_enforced() {
    // `MAX_INSTRUCTIONS` bounds the AST as well as the bytecode, so a hostile
    // chain cannot build an unbounded tree before compilation rejects it.
    let mut source = String::from("policy \"huge\" { allow true");
    while source.len() < MAX_SOURCE_LEN - 32 {
        source.push_str("&&true");
    }
    source.push_str("; }");

    assert!(matches!(
        Policy::compile(&source),
        Err(PolicyError::TooManyInstructions { .. })
    ));
}

#[test]
fn simple_policy_without_oracles() {
    assert!(eval(r#"policy "always" { allow true; }"#, &[]).unwrap());
    assert!(!eval(r#"policy "never" { allow false; }"#, &[]).unwrap());
}

fn code_offset(bytes: &[u8]) -> usize {
    let mut position = 5;
    let name_len = u16::from_le_bytes([bytes[position], bytes[position + 1]]) as usize;
    position += 2 + name_len;

    let oracle_count = u16::from_le_bytes([bytes[position], bytes[position + 1]]) as usize;
    position += 2;
    for _ in 0..oracle_count {
        let oracle_len = u16::from_le_bytes([bytes[position], bytes[position + 1]]) as usize;
        position += 2 + oracle_len + 1;
    }

    position + 2
}

fn first_oracle_name_offset(bytes: &[u8]) -> usize {
    let mut position = 5;
    let name_len = u16::from_le_bytes([bytes[position], bytes[position + 1]]) as usize;
    position += 2 + name_len;
    position += 2; // oracle count
    position + 2 // past the first oracle's name length
}

fn arbitrary_oracle_input(policy: &Policy) -> OracleInput {
    policy
        .oracles()
        .iter()
        .map(|oracle| {
            let value = match &oracle.ty {
                Type::Int => Value::Int(0),
                Type::Bool => Value::Bool(false),
                Type::Bytes => Value::Bytes(Vec::new()),
                Type::List(_) => Value::List(Vec::new()),
            };
            (oracle.name.clone(), value)
        })
        .collect()
}

proptest! {
    #[test]
    fn compile_never_panics(source in any::<String>()) {
        let _ = Policy::compile(&source);
    }

    #[test]
    fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(policy) = Policy::from_bytecode(&bytes) {
            let encoded = policy.to_bytecode();
            let decoded = Policy::from_bytecode(&encoded).expect("re-encoded policy decodes");
            prop_assert_eq!(policy.id(), decoded.id());
            let _ = policy.evaluate(&arbitrary_oracle_input(&policy));
        }
    }
}
