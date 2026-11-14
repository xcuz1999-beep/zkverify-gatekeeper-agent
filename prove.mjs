// Field encoding + Groth16 proving for the official gatekeeper circuit.
//
// All task values become BN254 field elements: integers pass through,
// hex strings are parsed as bigints, everything is reduced mod p.
// The task_id string encoding is switchable via TASK_ID_ENCODING
// (keccak | sha256 | ascii | hex-digits) — the platform does not publish
// it; practice mode is where the working scheme is confirmed.
import { createHash, randomBytes } from 'node:crypto';
import { keccak256, stringToHex } from 'viem';
import * as snarkjs from 'snarkjs';

export const P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const mod = (x) => ((x % P) + P) % P;

export function field(x) {
  if (typeof x === 'bigint') return mod(x).toString();
  if (typeof x === 'number') return mod(BigInt(x)).toString();
  const s = String(x).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return mod(BigInt(s)).toString();
  if (/^-?\d+$/.test(s)) return mod(BigInt(s)).toString();
  if (/^[0-9a-fA-F]+$/.test(s) && s.length >= 20) return mod(BigInt('0x' + s)).toString();
  throw new Error('cannot encode field: ' + s.slice(0, 40));
}

export function taskIdToField(taskId, encoding = 'keccak') {
  switch (encoding) {
    case 'keccak':
      return mod(BigInt(keccak256(stringToHex(taskId)))).toString();
    case 'sha256':
      return mod(BigInt('0x' + createHash('sha256').update(taskId).digest('hex'))).toString();
    case 'ascii': {
      const hex = Buffer.from(taskId, 'utf8').toString('hex');
      return hex ? mod(BigInt('0x' + hex)).toString() : '0';
    }
    case 'hex-digits': {
      const digits = taskId.replace(/^gk_/, '').replace(/[^0-9a-fA-F]/g, '');
      return digits ? mod(BigInt('0x' + digits)).toString() : '0';
    }
    default:
      throw new Error('unknown TASK_ID_ENCODING ' + encoding);
  }
}

export function randomSalt() {
  return mod(BigInt('0x' + randomBytes(31).toString('hex'))).toString();
}

export function circuitInputs(task, decision, salt, encoding) {
  const i = task.input;
  return {
    minimum: field(i.minimum),
    publicBalance: field(i.public_balance),
    amount: field(i.amount),
    maxTransfer: field(i.max_transfer),
    recipient: field(i.recipient),
    conditionRecipient: field(i.condition_recipient),
    expiryBlock: field(i.expiry_block),
    currentBlock: field(i.current_block),
    taskId: taskIdToField(task.task_id, encoding),
    salt,
    decision: decision === 'APPROVE' ? '1' : '0',
    registeredVkHash: field(i.registered_vk),
    proofVkHash: field(i.proof_vk),
  };
}

const WASM = new URL('./circuits/gatekeeper.wasm', import.meta.url).pathname;
const ZKEY = new URL('./circuits/gatekeeper_final.zkey', import.meta.url).pathname;
// Lazy + guarded: module import must never die on the VK file (on
// serverless bundles a top-level read can fail before any handler runs).
import { readFileSync } from 'node:fs';
let VK = null;
function loadVK() {
  if (VK) return VK;
  VK = JSON.parse(readFileSync(new URL('./circuits/gatekeeper_vk.json', import.meta.url), 'utf8'));
  return VK;
}

export async function prove(inputs) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
  return { proof, publicSignals };
}

export async function verifyProof(proof, publicSignals) {
  return snarkjs.groth16.verify(loadVK(), publicSignals, proof);
}
