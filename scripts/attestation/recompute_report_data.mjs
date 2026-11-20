// Recomputes the per-execution TDX report_data of one OutLayer task and compares it with the
// quote the worker attached. Uses Node's built-in crypto only; no dependencies.
//
// Usage: node recompute_report_data.mjs <vector.json>
//
// The vector holds the coordinator's attestation record, the execution_requested event of the
// same task, and the expected report_data. Exit code 0 on match, 1 on mismatch.
//
// Encoding (the worker's generate_task_attestation, worker/src/tdx_attestation.rs):
//   SHA-256( task_type ‖ task_id as i64 LE ‖ repo ‖ commit ‖ build_target ‖ wasm_hash ‖
//            input_hash ‖ output_hash ‖ block_height as u64 LE ‖ caller_account_id ‖
//            project_id ‖ secrets_ref ‖ timestamp as i64 LE ‖ attached_usd )
// Strings are their UTF-8 bytes as recorded (hashes are hex text). An absent optional field
// (null) contributes no bytes. report_data[0..32] is the digest, report_data[32..64] is zero.
// The quote's report_data sits at TD-report body offset 520, after the 48-byte quote header.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const HEADER_LEN = 48;
const REPORT_DATA_OFFSET = HEADER_LEN + 520;
const TDX_TEE_TYPE = 0x81;

function i64le(n) {
  const b = Buffer.alloc(8);
  b.writeBigInt64LE(BigInt(n));
  return b;
}

function u64le(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
}

function text(s) {
  return Buffer.from(String(s), "utf8");
}

function taskFields(v) {
  const r = v.record;
  const o = v.onchain;
  return [
    text(r.task_type),
    i64le(r.task_id),
    o.repo === null || o.repo === undefined ? null : text(o.repo),
    o.commit === null || o.commit === undefined ? null : text(o.commit),
    text(r.build_target),
    text(r.wasm_hash),
    text(r.input_hash),
    text(r.output_hash),
    r.block_height === null || r.block_height === undefined ? null : u64le(r.block_height),
    text(r.caller_account_id),
    o.project_id === null || o.project_id === undefined ? null : text(o.project_id),
    o.secrets_ref === null || o.secrets_ref === undefined ? null : text(o.secrets_ref),
    i64le(r.timestamp),
    o.attached_usd === null || o.attached_usd === undefined ? null : text(o.attached_usd),
  ];
}

function sha256(parts) {
  const h = createHash("sha256");
  for (const p of parts) if (p) h.update(p);
  return h.digest();
}

function main() {
  const path = process.argv[2];
  if (!path) {
    console.error("usage: node recompute_report_data.mjs <vector.json>");
    process.exit(2);
  }
  const v = JSON.parse(readFileSync(path, "utf8"));
  const failures = [];

  const inputHash = createHash("sha256").update(v.onchain.input_data, "utf8").digest("hex");
  if (inputHash !== v.record.input_hash) failures.push(`input_hash: sha256(input_data) is ${inputHash}`);

  const quote = Buffer.from(v.record.tdx_quote, "base64");
  const version = quote.readUInt16LE(0);
  const teeType = quote.readUInt32LE(4);
  if (version !== 4) failures.push(`quote version is ${version}, expected 4`);
  if (teeType !== TDX_TEE_TYPE) failures.push(`quote TEE type is 0x${teeType.toString(16)}, expected 0x81 (TDX)`);

  const attested = quote.subarray(REPORT_DATA_OFFSET, REPORT_DATA_OFFSET + 64);
  if (!attested.subarray(32).every((b) => b === 0)) failures.push("report_data[32..64] is not zero");

  const digest = sha256(taskFields(v));
  const recomputed = Buffer.concat([digest, Buffer.alloc(32)]).toString("hex");
  const attestedHex = attested.toString("hex");

  console.log(`recomputed report_data: ${recomputed}`);
  console.log(`quote report_data:      ${attestedHex}`);
  if (v.expected_report_data !== undefined && v.expected_report_data !== attestedHex) {
    failures.push("expected_report_data in the vector does not equal the quote's report_data");
  }
  if (recomputed !== attestedHex) failures.push("recomputed report_data does not equal the quote's");

  if (failures.length) {
    for (const f of failures) console.error(`MISMATCH: ${f}`);
    process.exit(1);
  }
  console.log("MATCH");
}

main();
