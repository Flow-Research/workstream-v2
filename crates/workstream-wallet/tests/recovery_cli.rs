use age::secrecy::ExposeSecret;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};
use workstream_core::{ActionType, FeePayer, FeeSpec, Transaction};
use workstream_tx::{TxBuilder, TxValidator};
use workstream_wallet::{RecoveryKey, Wallet};

#[test]
fn fresh_home_signs_reviewed_backup_and_rejects_changed_draft() {
    let home = tempfile::tempdir().unwrap();
    let identity = RecoveryKey::generate();
    let account = {
        let original = Wallet::generate(42).unwrap();
        fs::write(
            home.path().join("backup.age"),
            original.backup(&identity.to_public()).unwrap(),
        )
        .unwrap();
        original.account()
    }; // No original Wallet or local keystore available to either process.
    let mut draft = TxBuilder::new()
        .chain_id(42)
        .account(account)
        .nonce(0, 7)
        .fee(FeeSpec {
            payer: FeePayer::Self_,
            asset_id: 0,
            max_fee: 100,
        })
        .add_action(ActionType::ActorRegister, vec![1])
        .build()
        .unwrap();
    let path = home.path().join("draft.json");
    fs::write(&path, serde_json::to_vec(&draft).unwrap()).unwrap();
    let preview = Command::new(env!("CARGO_BIN_EXE_workstream-inspect"))
        .env_clear()
        .env("HOME", home.path())
        .current_dir(home.path())
        .stdin(fs::File::open(&path).unwrap())
        .output()
        .unwrap();
    assert!(preview.status.success());
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(preview["account"], account.to_string());
    assert_eq!(preview["network"], 42);
    assert_eq!(preview["actions"][0]["type"], "ActorRegister");
    let sign = || {
        let mut child = Command::new(env!("CARGO_BIN_EXE_workstream-sign"))
            .env_clear()
            .env("HOME", home.path())
            .current_dir(home.path())
            .args([
                "--network",
                "42",
                "--backup",
                "backup.age",
                "--draft",
                "draft.json",
                "--approve",
                preview["approval_digest"].as_str().unwrap(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(
            child.stdin.take().unwrap(),
            "{}",
            identity.to_string().expose_secret()
        )
        .unwrap();
        child.wait_with_output().unwrap()
    };
    let accepted = sign();
    assert!(accepted.status.success() && accepted.stderr.is_empty());
    let signed: Transaction = serde_json::from_slice(&accepted.stdout).unwrap();
    TxValidator::new().validate(&signed).unwrap();
    assert_eq!(signed.account, account);
    assert_eq!(
        workstream_crypto::signature::tx_message_hash(&signed)
            .unwrap()
            .to_string(),
        preview["approval_digest"]
    );
    draft.actions[0].payload.push(2);
    fs::write(path, serde_json::to_vec(&draft).unwrap()).unwrap();
    let rejected = sign();
    assert!(!rejected.status.success() && rejected.stdout.is_empty());
    assert_eq!(
        rejected.stderr,
        b"draft does not match signing approval or wallet\n"
    );
}
