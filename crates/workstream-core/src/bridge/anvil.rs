//! Local development settlement via Foundry `cast` and a trusted deployment
//! of `contracts/LocalSettlement.sol`. One confirmation on an automining Anvil
//! chain is sufficient here; this is not a public-chain finality policy.
use super::{Payout, SettlementRail};
use crate::{Error, Result, H256};
use std::{net::SocketAddr, process::Command};

pub struct AnvilSettlement {
    endpoint: String,
    contract: String,
    operator: String,
}

impl AnvilSettlement {
    pub fn new(endpoint: SocketAddr, contract: [u8; 20], operator: [u8; 20]) -> Result<Self> {
        if !endpoint.ip().is_loopback() || contract == [0; 20] || operator == [0; 20] {
            return Err(Error::Config(
                "expected loopback Anvil and nonzero vault/operator".into(),
            ));
        }
        Ok(Self {
            endpoint: format!("http://{endpoint}"),
            contract: format!("0x{}", hex::encode(contract)),
            operator: format!("0x{}", hex::encode(operator)),
        })
    }

    fn cast(&self, method: &str, abi: &str, args: &[String]) -> Result<String> {
        let mut command = Command::new("cast");
        command.args([method, "--rpc-url", &self.endpoint, "--rpc-timeout", "10"]);
        if method == "send" {
            command.args(["--unlocked", "--from", &self.operator, "--timeout", "30"]);
        }
        let out = command
            .args([&self.contract, abi])
            .args(args)
            .output()
            .map_err(|e| Error::Io(format!("launch cast: {e}")))?;
        if !out.status.success() {
            return Err(Error::Io(format!(
                "cast {method}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        String::from_utf8(out.stdout).map_err(|e| Error::Serialization(e.to_string()))
    }
}

impl SettlementRail for AnvilSettlement {
    fn pay_once(&mut self, p: &Payout) -> Result<H256> {
        let address = p.recipient.as_bytes();
        if address[..12] != [0; 12] {
            return Err(Error::Validation(
                "recipient is not a zero-extended EVM address".into(),
            ));
        }
        let args = [
            p.domain.to_string(),
            p.asset.to_string(),
            p.escrow_id.to_string(),
            format!("0x{}", hex::encode(&address[12..])),
            p.amount.to_string(),
        ];
        let confirmation = || {
            let raw = self.cast(
                "call",
                "confirmation(bytes32,bytes32,bytes32,address,uint128)(bytes32)",
                &args,
            )?;
            H256::from_hex(
                raw.trim()
                    .strip_prefix("0x")
                    .ok_or_else(|| Error::Serialization("invalid vault reply".into()))?,
            )
        };
        let previous = confirmation()?;
        if previous != H256::ZERO {
            return Ok(previous);
        }
        self.cast(
            "send",
            "pay(bytes32,bytes32,bytes32,address,uint128)",
            &args,
        )?;
        let receipt = confirmation()?;
        if receipt == H256::ZERO {
            return Err(Error::State("vault did not confirm payment".into()));
        }
        Ok(receipt)
    }
}
