/**
 * Rust/TypeScript serialization + signing agreement (issue #130).
 *
 * Reads the same checked-in vectors.json as the Rust unit tests and proves a
 * browser (Node WebCrypto here) derives the same Ed25519 public key, signature
 * and domain-separated hash. Run with `npm test`.
 */
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { strict as assert } from "node:assert";

interface Vectors {
  api_version: number;
  seed: string;
  message: string;
  public_key: string;
  signature: string;
  domain: string;
  payload: string;
  domain_hash: string;
}

const vectors: Vectors = JSON.parse(
  readFileSync(new URL("../../testdata/vectors.json", import.meta.url), "utf8"),
);

// RFC 8410 PKCS#8 wrapper for the Ed25519 seed, identical to generation.
function privateKeyFromSeed(seed: Buffer) {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({ key: Buffer.concat([prefix, seed]), format: "der", type: "pkcs8" });
}

async function main(): Promise<void> {
  assert.equal(vectors.api_version, 1);

  const seed = Buffer.from(vectors.seed, "hex");
  const priv = privateKeyFromSeed(seed);
  const spki = createPublicKey(priv).export({ format: "der", type: "spki" });
  const pub = spki.subarray(spki.length - 32);
  assert.equal(
    pub.toString("hex"),
    vectors.public_key,
    "Ed25519 public key must match the Rust vector",
  );

  const message = Buffer.from(vectors.message, "hex");
  // WebCrypto proves the browser path can verify the signature made by Rust.
  const verifyKey = await globalThis.crypto.subtle.importKey(
    "raw",
    pub,
    "Ed25519",
    false,
    ["verify"],
  );
  const signature = Buffer.from(vectors.signature, "hex");
  assert.equal(
    await globalThis.crypto.subtle.verify("Ed25519", verifyKey, signature, message),
    true,
    "browser must verify the Rust-produced signature",
  );

  const domainHash = createHash("sha256")
    .update(Buffer.concat([
      Buffer.from("WS:v1:api:"),
      Buffer.from(vectors.domain),
      Buffer.from(":"),
      Buffer.from(vectors.payload),
    ]))
    .digest();
  assert.equal(
    domainHash.toString("hex"),
    vectors.domain_hash,
    "domain-separated hash must match Rust",
  );

  console.log("Rust/TypeScript vectors agree: ed25519 key, signature, domain hash");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
