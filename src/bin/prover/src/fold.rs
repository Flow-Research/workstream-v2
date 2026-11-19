//! Recursive composition of two independently proved STF transitions.
use risc0_zkvm::{sha::Digest, ExecutorEnv, ExternalProver, Prover, ProverOpts, Receipt};
use workstream_core::{Error, Result, H256};
use workstream_stf::receipt::Pair;

fn invalid(e: impl std::fmt::Display) -> Error {
    Error::InvalidProof(e.to_string())
}

pub fn aggregate(
    image: &[u8],
    approved_fold: H256,
    pair: &Pair,
    leaves: [Receipt; 2],
) -> Result<Receipt> {
    if super::risc0::image_id(image)? != approved_fold {
        return Err(invalid("unapproved aggregation guest"));
    }
    let bytes = postcard::to_allocvec(pair).map_err(invalid)?;
    let mut env = ExecutorEnv::builder();
    env.write_slice(&(bytes.len() as u32).to_le_bytes())
        .write_slice(&bytes);
    for leaf in leaves {
        env.add_assumption(leaf);
    }
    let receipt = ExternalProver::new("local", "r0vm")
        .prove_with_opts(
            env.build().map_err(invalid)?,
            image,
            &ProverOpts::succinct(),
        )
        .map_err(invalid)?
        .receipt;
    verify(&receipt, approved_fold, pair)?;
    Ok(receipt)
}

pub fn verify(receipt: &Receipt, approved_fold: H256, expected: &Pair) -> Result<()> {
    expected.validate()?;
    receipt
        .verify(Digest::try_from(approved_fold.as_bytes().as_slice()).map_err(invalid)?)
        .map_err(invalid)?;
    if receipt.journal.bytes != postcard::to_allocvec(expected).map_err(invalid)? {
        return Err(invalid("unexpected batch journal"));
    }
    Ok(())
}
