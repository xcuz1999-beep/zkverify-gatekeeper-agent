// Deterministic decision logic for Proof Gatekeeper.
// Order follows the official trap documentation: the first failed check
// names the reason code. Fail closed: malformed input is a rejection.
//
// Returns { decision: 'APPROVE'|'REJECT', reason_code: string }

export const REASONS = {
  VALID: 'VALID_CONDITION',
  REUSED: 'PROOF_REUSED',
  VK: 'VK_SUBSTITUTION',
  THRESHOLD: 'THRESHOLD_MISMATCH',
  EXPIRED: 'EXPIRED_CONDITION',
  RECIPIENT: 'RECIPIENT_MISMATCH',
  AMOUNT: 'AMOUNT_OVERFLOW',
};

const hexEq = (a, b) =>
  typeof a === 'string' && typeof b === 'string' &&
  a.toLowerCase() === b.toLowerCase();

function toBig(x) {
  if (typeof x === 'number') return BigInt(x);
  if (typeof x === 'string' && /^-?\d+$/.test(x.trim())) return BigInt(x.trim());
  return null;
}

// seenProofTxs: Set<string> of proof_tx references already approved.
export function decide(input, seenProofTxs) {
  if (!input || typeof input !== 'object') {
    return { decision: 'REJECT', reason_code: REASONS.VK };
  }
  const {
    registered_vk, proof_vk, minimum, public_balance,
    expiry_block, current_block, recipient, condition_recipient,
    amount, max_transfer, proof_tx,
  } = input;

  // 1. Proof reuse: a reference that was already approved never re-enters.
  if (typeof proof_tx === 'string' && seenProofTxs.has(proof_tx.toLowerCase())) {
    return { decision: 'REJECT', reason_code: REASONS.REUSED };
  }
  // 2. The proof must have been produced under the registered VK.
  if (!hexEq(proof_vk, registered_vk)) {
    return { decision: 'REJECT', reason_code: REASONS.VK };
  }
  // 3. The disclosed public balance must meet the condition minimum.
  const min = toBig(minimum), bal = toBig(public_balance);
  if (min === null || bal === null || bal < min) {
    return { decision: 'REJECT', reason_code: REASONS.THRESHOLD };
  }
  // 4. The condition must not be expired at the current block.
  const exp = toBig(expiry_block), cur = toBig(current_block);
  if (exp === null || cur === null || cur >= exp) {
    return { decision: 'REJECT', reason_code: REASONS.EXPIRED };
  }
  // 5. The paid recipient must be the condition's recipient.
  if (!hexEq(recipient, condition_recipient)) {
    return { decision: 'REJECT', reason_code: REASONS.RECIPIENT };
  }
  // 6. The amount must fit the single-transfer cap.
  const amt = toBig(amount), cap = toBig(max_transfer);
  if (amt === null || cap === null || amt > cap) {
    return { decision: 'REJECT', reason_code: REASONS.AMOUNT };
  }
  return { decision: 'APPROVE', reason_code: REASONS.VALID };
}
