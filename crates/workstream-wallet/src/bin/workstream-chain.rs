//! Bounded, read-only diagnostics for the connected node's loopback RPC.
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::{net::Ipv4Addr, process::ExitCode, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 8545)]
    port: u16,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report verified and indexed heights, including stale reads.
    Status,
    /// Check freshness and the writer's queue endpoint.
    Doctor,
    /// Check freshness and read a single page of verified receipts.
    Smoke,
}

async fn read_rpc(port: u16, method: &str, params: Value) -> Result<Value, &'static str> {
    let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|_| "node unavailable")?;
    let mut req = json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}).to_string();
    req.push('\n');
    socket
        .write_all(req.as_bytes())
        .await
        .map_err(|_| "node unavailable")?;
    const MAX: u64 = 64 * 1024;
    let mut frame = Vec::new();
    BufReader::new(socket.take(MAX + 1))
        .read_until(b'\n', &mut frame)
        .await
        .map_err(|_| "read failed")?;
    if frame.len() as u64 > MAX || frame.last() != Some(&b'\n') {
        return Err("invalid reply frame");
    }
    let mut reply: Value = serde_json::from_slice(&frame).map_err(|_| "invalid RPC reply")?;
    if reply["jsonrpc"] != "2.0"
        || reply["id"] != 1
        || !reply["result"].is_object()
        || reply.get("error").is_some()
    {
        return Err("node read unavailable");
    }
    Ok(reply["result"].take())
}

async fn diagnose(args: Args) -> Result<(Value, bool), &'static str> {
    let projection = read_rpc(args.port, "workstream.indexer.getStatus", Value::Null).await?;
    let indexed = projection["indexed_height"]
        .as_u64()
        .ok_or("missing index cursor")?;
    let tip = read_rpc(args.port, "workstream.node.verifiedTip", Value::Null).await?;
    let verified = tip["height"].as_u64().ok_or("missing verified tip")?;
    let lag = verified
        .checked_sub(indexed)
        .ok_or("index ahead of verified tip; retry")?;
    let mut report = json!({"verified_height":verified,"indexed_height":indexed,"lag":lag,"freshness":if lag==0 {"current"} else {"stale"}});
    match args.command {
        Command::Status => return Ok((report, true)),
        Command::Doctor => {
            let queue = read_rpc(
                args.port,
                "workstream.sequencer.getMempoolStatus",
                Value::Null,
            )
            .await?;
            report["pending_transactions"] = queue["pending_count"]
                .as_u64()
                .ok_or("invalid writer response")?
                .into();
        }
        Command::Smoke => {
            let page = read_rpc(
                args.port,
                "workstream.indexer.getPage",
                json!({"kind":"receipts","limit":1}),
            )
            .await?;
            if page["kind"] != "receipts"
                || page["items"].as_array().is_none_or(|items| items.len() > 1)
            {
                return Err("invalid receipt page");
            }
            report["receipt_page_read"] = true.into();
        }
    }
    Ok((report, lag == 0))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match tokio::time::timeout(Duration::from_secs(5), diagnose(Args::parse())).await {
        Ok(Ok((value, ok))) => {
            println!("{value}");
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Ok(Err(message)) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("diagnostics timed out");
            ExitCode::FAILURE
        }
    }
}
