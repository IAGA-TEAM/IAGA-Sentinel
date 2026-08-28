#!/usr/bin/env node
// Offline verifier for IAGA Sentinel signed receipt chains, for Node/TypeScript.
//
// The Node/TS half of the multilingual verifier (roadmap 1.3 "verifier
// sovereignty"): an auditor on a JS stack reaches the *same verdict* as the
// canonical Rust `iaga-verify`, from the same exported chain, with **no
// third-party dependencies** — only Node's built-in `crypto` (Ed25519 +
// SHA-256). Run it:
//
//   node verify.mjs chain.json --key <hex-ed25519-pubkey>
//
// Exit codes match the Rust binary: 0 valid, 1 broken/empty, 2 usage, 3
// IO/parse/unsupported.
//
// Signed bytes are `serde_json::to_vec(&ReceiptBody)` — compact JSON in
// struct-declaration order. The export already stores body fields in that
// order (serde emits them so; JSON.parse preserves key order), so the signed
// bytes are the receipt object minus its `signature` key, re-stringified
// compactly. For the float-free values every OSS receipt carries,
// `JSON.stringify` is byte-identical to serde_json. A receipt carrying
// floating-point values (e.g. `ml_scores`) is refused, not guessed.
//
// Parity is proven by verify.smoke.mjs against ../conformance/golden_chain.json
// (signed by the canonical Rust code) plus an RFC 8032 known-answer vector.

import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import process from "node:process";
import { pathToFileURL } from "node:url";

// DER SPKI prefix for an Ed25519 public key; raw 32-byte key is appended.
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Verify an Ed25519 signature with the cofactorless check that matches the
 * canonical `ed25519_dalek::VerifyingKey::verify`.
 * @param {Buffer} publicKey 32 raw bytes
 * @param {Buffer} signature 64 raw bytes
 * @param {Buffer} message
 * @returns {boolean}
 */
export function ed25519Verify(publicKey, signature, message) {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, publicKey]),
      format: "der",
      type: "spki",
    });
    return nodeVerify(null, message, key, signature);
  } catch {
    return false;
  }
}

/** ed25519-<first 16 bytes of SHA-256(pubkey), hex>. */
function keyId(publicKey) {
  return "ed25519-" + createHash("sha256").update(publicKey).digest().subarray(0, 16).toString("hex");
}

/** A receipt shape this dependency-free verifier won't canonicalize (e.g. float ml_scores). */
export class Unsupported extends Error {}

function containsFloat(value) {
  if (typeof value === "number") return !Number.isInteger(value);
  if (Array.isArray(value)) return value.some(containsFloat);
  if (value && typeof value === "object") return Object.values(value).some(containsFloat);
  return false;
}

/** Recover the exact signed bytes: the receipt object minus `signature`, compact JSON in original key order. */
function signingBytes(receipt) {
  /** @type {Record<string, unknown>} */
  const body = {};
  for (const [k, v] of Object.entries(receipt)) {
    if (k !== "signature") body[k] = v;
  }
  if (containsFloat(body)) {
    throw new Unsupported(
      "receipt body contains floating-point values (e.g. ml_scores); verify with the canonical Rust iaga-verify",
    );
  }
  return Buffer.from(JSON.stringify(body), "utf8");
}

/**
 * @typedef {Object} VerifyResult
 * @property {boolean} ok
 * @property {string} runId
 * @property {number} receiptCount
 * @property {string} signerKeyId
 * @property {"pinned"|"embedded"} keySource
 * @property {string=} reason
 * @property {number=} brokenSeq
 * @property {boolean=} empty
 */

/**
 * Verify an exported receipt chain. With `pinnedKeyHex` the chain is checked
 * against that trusted key; otherwise the self-asserted embedded key is used.
 * @param {Record<string, any>} exportObj
 * @param {string=} pinnedKeyHex
 * @returns {VerifyResult}
 */
export function verifyExport(exportObj, pinnedKeyHex) {
  /** @type {"pinned"|"embedded"} */
  let keySource;
  let keyHex;
  if (pinnedKeyHex != null) {
    keyHex = String(pinnedKeyHex).trim();
    keySource = "pinned";
  } else {
    keyHex = String(exportObj.signer_verifying_key ?? "").trim();
    keySource = "embedded";
  }

  if (!/^[0-9a-fA-F]*$/.test(keyHex) || keyHex.length !== 64) {
    throw new RangeError(`invalid public key: expected 32 hex-encoded bytes, got ${keyHex.length / 2}`);
  }
  const publicKey = Buffer.from(keyHex, "hex");
  const kid = keyId(publicKey);
  const claimed = String(exportObj.signer_key_id ?? "");
  const runId = String(exportObj.run_id ?? "");
  const receipts = Array.isArray(exportObj.receipts) ? exportObj.receipts : [];

  /** @returns {VerifyResult} */
  const broken = (seq, reason) => ({ ok: false, runId, receiptCount: 0, signerKeyId: claimed, keySource, reason, brokenSeq: seq });

  // Bind the claimed signer id to the key that actually verifies.
  if (claimed !== kid) {
    return broken(0, `signer_key_id mismatch: export claims ${claimed} but the verifying key is ${kid}`);
  }
  if (receipts.length === 0) {
    return { ok: false, runId, receiptCount: 0, signerKeyId: claimed, keySource, reason: "empty chain", empty: true };
  }

  /** @type {string|null} */
  let expectedParent = null;
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    const seq = r.seq;
    if (String(r.signer_key_id ?? "") !== kid) {
      return broken(seq, `receipt seq ${seq} claims signer ${r.signer_key_id} but the verifying key is ${kid}`);
    }
    if (String(r.run_id ?? "") !== runId) {
      return broken(seq, `run_id mismatch: expected ${runId} got ${r.run_id}`);
    }
    if (seq !== i) {
      return broken(seq, `non-monotonic seq: expected ${i} got ${seq}`);
    }
    const parent = r.parent_hash ?? null;
    if (parent !== expectedParent) {
      return broken(seq, `parent_hash mismatch: expected ${expectedParent} got ${parent}`);
    }
    const message = signingBytes(r);
    let sig;
    try {
      sig = Buffer.from(String(r.signature), "hex");
    } catch {
      return broken(seq, "signature invalid: not hex");
    }
    if (!ed25519Verify(publicKey, sig, message)) {
      return broken(seq, "signature invalid");
    }
    expectedParent = createHash("sha256").update(message).digest("hex");
  }

  return { ok: true, runId, receiptCount: receipts.length, signerKeyId: claimed, keySource };
}

// --- CLI (mirrors the Rust `iaga-verify` surface and exit codes) ------------

const USAGE = "usage: iaga-verify <chain.json> [--key <hex-ed25519-pubkey>] [--expect-count <n>]";

/** @param {string[]} argv @returns {number} */
export function main(argv) {
  let path;
  let key;
  let expectCount;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--key" || a === "-k") {
      key = argv[++i];
      if (key === undefined) {
        process.stderr.write("iaga-verify: --key needs a hex public key\n");
        return 2;
      }
    } else if (a === "--expect-count") {
      // The one honest defence against tail truncation offline, and it has to
      // exist here too: README.md offers this verifier as the way to check a
      // chain with no build at all, and sdks/conformance/README.md promises all
      // three reach the same verdict with the same exit codes. Shipping the flag
      // only in the Rust binary made that promise false for exactly the reader
      // who cannot build Rust. Wording copied from the Rust verifier.
      const raw = argv[++i];
      if (raw === undefined) {
        process.stderr.write("iaga-verify: --expect-count needs a value\n");
        return 2;
      }
      if (!/^\d+$/.test(raw)) {
        process.stderr.write("iaga-verify: --expect-count needs a non-negative integer\n");
        return 2;
      }
      expectCount = Number(raw);
    } else if (a === "-h" || a === "--help") {
      process.stdout.write(USAGE + "\nVerifies the Ed25519 signatures and hash-chain links of a signed receipt chain.\n");
      return 0;
    } else if (path === undefined) {
      path = a;
    } else {
      process.stderr.write(`iaga-verify: unexpected argument: ${a}\n${USAGE}\n`);
      return 2;
    }
  }
  if (path === undefined) {
    process.stderr.write(USAGE + "\n");
    return 2;
  }

  let exportObj;
  try {
    exportObj = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    if (e && e.code === "ENOENT") {
      process.stderr.write(`iaga-verify: cannot read ${path}: ${e.message}\n`);
    } else {
      process.stderr.write(`iaga-verify: ${path} is not a valid chain export: ${e}\n`);
    }
    return 3;
  }

  let res;
  try {
    res = verifyExport(exportObj, key);
  } catch (e) {
    process.stderr.write(`iaga-verify: ${e instanceof Unsupported ? e.message : "verification error: " + e}\n`);
    return 3;
  }

  if (res.keySource === "embedded") {
    process.stderr.write(
      "warning: verifying against the key embedded in the export (self-asserted). " +
        "Pass --key with the expected public key to authenticate authorship.\n",
    );
  }
  if (res.ok) {
    if (expectCount !== undefined && res.receiptCount !== expectCount) {
      process.stderr.write(
        `CHAIN LENGTH MISMATCH  run_id=${res.runId}  receipts=${res.receiptCount}  expected=${expectCount}  signer=${res.signerKeyId}  key=${res.keySource}\n`,
      );
      process.stderr.write(
        `the chain is internally valid but not the length you anchored: ${res.receiptCount} of ${expectCount} receipts. A shorter valid chain is what tail truncation looks like.\n`,
      );
      return 1;
    }
    const last = Math.max(res.receiptCount - 1, 0);
    process.stdout.write(
      `CHAIN OK  run_id=${res.runId}  receipts=${res.receiptCount}  seq=0..${last}  signer=${res.signerKeyId}  key=${res.keySource}\n`,
    );
    return 0;
  }
  if (res.empty) {
    process.stderr.write(`CHAIN EMPTY  run_id=${res.runId}\n`);
    return 1;
  }
  process.stderr.write(`CHAIN BROKEN  run_id=${res.runId}  seq=${res.brokenSeq}  reason=${res.reason}\n`);
  return 1;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  process.exit(main(process.argv.slice(2)));
}
