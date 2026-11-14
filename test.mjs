// Local end-to-end test: boots the server with a test secret, replays
// envelopes for preflight + every documented trap type, and checks the
// decision, reason code, response signature, and proof presence.
import { spawn } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { verifyProof } from './prove.mjs';

const SECRET = 'test-secret-for-local-checks';
const PORT = 18080;
const BASE = `http://127.0.0.1:${PORT}`;
const sign = (s) => createHmac('sha256', SECRET).update(s).digest('hex');

const VK = '0x' + '11'.repeat(32);
const VK2 = '0x' + '22'.repeat(32);
const ADDR = '0x' + 'aa'.repeat(20);
const ADDR2 = '0x' + 'bb'.repeat(20);

function task(id, overrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: id,
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460',
      expiry_block: 19842201, current_block: 19832000,
      recipient: ADDR, condition_recipient: ADDR,
      amount: '500', max_transfer: '1000', proof_tx: '0x' + 'cc'.repeat(32),
      ...overrides,
    },
  };
}

async function post(payload) {
  const raw = JSON.stringify(payload);
  const res = await fetch(BASE + '/agent', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': sign(raw) },
    body: raw,
  });
  const text = await res.text();
  return { status: res.status, sig: res.headers.get('x-agent-games-signature'), body: text, json: JSON.parse(text) };
}

let pass = 0, fail = 0;
function check(name, cond, extra = '') {
  if (cond) { pass++; console.log('PASS', name); }
  else { fail++; console.log('FAIL', name, extra); }
}

const server = spawn('node', ['server.mjs'], {
  cwd: new URL('.', import.meta.url).pathname,
  env: { ...process.env, PORT, AGENT_GAMES_HMAC_SECRET: SECRET, DATA_DIR: './data-test' },
  stdio: 'pipe',
});
server.stderr.on('data', (d) => process.stderr.write('[server] ' + d));
for (let i = 0; i < 60; i++) {
  try { await fetch(BASE + '/health'); break; } catch { await new Promise((r) => setTimeout(r, 1000)); }
}

try {
  const health = await (await fetch(BASE + '/health')).json();
  check('health', health.ok === true);

  const pre = await post({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
  check('preflight shape', pre.json.ok === true && pre.json.protocolVersion === 'v1');
  check('preflight signed', pre.sig === sign(pre.body));

  const bad = await fetch(BASE + '/agent', { method: 'POST', headers: { 'content-type': 'application/json', 'x-agent-games-signature': 'deadbeef' }, body: '{}' });
  check('bad signature rejected', bad.status === 401);

  const valid = await post(task('gk_t_valid'));
  check('valid -> APPROVE/VALID_CONDITION', valid.json.decision === 'APPROVE' && valid.json.reason_code === 'VALID_CONDITION', JSON.stringify(valid.json).slice(0, 200));
  check('valid has proof', !!valid.json.proof && Array.isArray(valid.json.public_signals));
  check('valid proof verifies locally', valid.json.proof ? await verifyProof(valid.json.proof, valid.json.public_signals) : false);
  check('response signed', valid.sig === sign(valid.body));

  const retry = await post(task('gk_t_valid'));
  check('retry returns identical body', retry.body === valid.body);

  const reused = await post(task('gk_t_reused', {}));
  check('reused proof_tx -> REJECT/PROOF_REUSED, no proof', reused.json.decision === 'REJECT' && reused.json.reason_code === 'PROOF_REUSED' && !reused.json.proof);

  const vk = await post(task('gk_t_vk', { proof_vk: VK2, proof_tx: '0x' + 'd1'.repeat(32) }));
  check('vk trap', vk.json.decision === 'REJECT' && vk.json.reason_code === 'VK_SUBSTITUTION' && !!vk.json.proof);

  const thr = await post(task('gk_t_thr', { public_balance: '999', proof_tx: '0x' + 'd2'.repeat(32) }));
  check('threshold trap', thr.json.decision === 'REJECT' && thr.json.reason_code === 'THRESHOLD_MISMATCH' && !!thr.json.proof);

  const exp = await post(task('gk_t_exp', { current_block: 19842201, proof_tx: '0x' + 'd3'.repeat(32) }));
  check('expiry trap', exp.json.decision === 'REJECT' && exp.json.reason_code === 'EXPIRED_CONDITION' && !!exp.json.proof);

  const rec = await post(task('gk_t_rec', { recipient: ADDR2, proof_tx: '0x' + 'd4'.repeat(32) }));
  check('recipient trap', rec.json.decision === 'REJECT' && rec.json.reason_code === 'RECIPIENT_MISMATCH' && !!rec.json.proof);

  const amt = await post(task('gk_t_amt', { amount: '1001', proof_tx: '0x' + 'd5'.repeat(32) }));
  check('amount trap', amt.json.decision === 'REJECT' && amt.json.reason_code === 'AMOUNT_OVERFLOW' && !!amt.json.proof);
} finally {
  server.kill();
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
