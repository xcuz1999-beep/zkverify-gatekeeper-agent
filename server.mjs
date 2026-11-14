// zeo9-gatekeeper — Proof Gatekeeper agent for zkVerify Agent Games.
//
// POST /agent accepts platform envelopes signed with HMAC-SHA256
// (x-agent-games-signature over the raw body). Every response is signed
// the same way. Decisions are deterministic (checks.mjs); a local
// Groth16 proof from the official circuit accompanies every decision
// except PROOF_REUSED (reuse is not part of the circuit). Responses are
// cached per task_id (retries are idempotency keys) and the seen-set of
// approved proof references is persisted on disk.
try { process.loadEnvFile(new URL('./.env', import.meta.url).pathname); } catch {}
import { createServer } from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { decide, REASONS } from './checks.mjs';
import { circuitInputs, prove, verifyProof, randomSalt } from './prove.mjs';

const PORT = process.env.PORT || 8080;
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const ENCODING = process.env.TASK_ID_ENCODING || 'keccak';
const DATA_DIR = process.env.DATA_DIR || new URL('./data', import.meta.url).pathname;
mkdirSync(DATA_DIR, { recursive: true });

if (!SECRET) console.error('WARNING: AGENT_GAMES_HMAC_SECRET is empty — signature checks will fail');

const seenFile = `${DATA_DIR}/seen.json`;
const cacheFile = `${DATA_DIR}/responses.json`;
const seen = new Set(existsSync(seenFile) ? JSON.parse(readFileSync(seenFile, 'utf8')) : []);
const cache = new Map(existsSync(cacheFile) ? JSON.parse(readFileSync(cacheFile, 'utf8')) : []);
const saveSeen = () => writeFileSync(seenFile, JSON.stringify([...seen]));
const saveCache = () => writeFileSync(cacheFile, JSON.stringify([...cache]));

const hmac = (data) => createHmac('sha256', SECRET).update(data).digest('hex');
function validSignature(rawBody, header) {
  if (!SECRET || typeof header !== 'string') return false;
  const expected = Buffer.from(hmac(rawBody), 'utf8');
  const given = Buffer.from(header.trim().toLowerCase(), 'utf8');
  return expected.length === given.length && timingSafeEqual(expected, given);
}

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

async function handleTask(task) {
  const taskId = task.task_id;
  if (cache.has(taskId)) {
    log('task', taskId, 'cache-hit');
    return cache.get(taskId);
  }
  const { decision, reason_code } = decide(task.input, seen);
  const response = { decision, reason_code, proof_tx: task.input?.proof_tx };
  if (reason_code !== REASONS.REUSED) {
    try {
      const inputs = circuitInputs(task, decision, randomSalt(), ENCODING);
      const t0 = Date.now();
      const { proof, publicSignals } = await prove(inputs);
      const ok = await verifyProof(proof, publicSignals);
      log('task', taskId, 'proof generated in', Date.now() - t0, 'ms, local verify:', ok);
      if (ok) {
        response.proof = proof;
        response.public_signals = publicSignals;
      } else {
        log('task', taskId, 'WARNING: local proof verification failed — sending decision only');
      }
    } catch (e) {
      log('task', taskId, 'proof failed (decision kept):', e.message?.slice(0, 160));
    }
  }
  if (typeof task.input?.proof_tx === 'string' &&
      (decision === 'APPROVE' || reason_code === REASONS.REUSED)) {
    seen.add(task.input.proof_tx.toLowerCase());
    saveSeen();
  }
  const body = JSON.stringify(response);
  cache.set(taskId, body);
  saveCache();
  log('task', taskId, decision, reason_code);
  return body;
}

const WILDCARD_PAGE = `<!doctype html><html><head><meta charset="utf-8">
<title>zeo9-gatekeeper — a proof-backed payment firewall</title>
<style>body{font-family:system-ui,sans-serif;max-width:44rem;margin:3rem auto;padding:0 1rem;line-height:1.55;color:#111}code{background:#f2f2f2;padding:.1rem .3rem;border-radius:.3rem}h1{font-size:1.6rem}</style></head>
<body><h1>zeo9-gatekeeper — a proof-backed payment firewall</h1>
<p><strong>Problem.</strong> AI agents increasingly initiate payments, and a valid zero-knowledge
proof only proves a statement — it does not prove the payment <em>should</em> happen. The proof can
verify perfectly while the verification key was swapped, the recipient differs from the agreed
condition, the terms expired, the amount exceeds its cap, or the same proof is replayed.
Approving on "proof verified" alone is how agent wallets get drained.</p>
<p><strong>What this agent does.</strong> It is a deterministic firewall that sits between a
payment request and its approval. Every field of the request is checked against the registered
condition in a fixed order (replay &rarr; verification key &rarr; threshold &rarr; expiry &rarr;
recipient &rarr; amount cap), the first failure names the rejection reason, and the decision
itself is returned with a Groth16 proof generated locally from the official gatekeeper circuit —
a circuit that <em>refuses to prove a wrong decision</em>. Transport is HMAC-SHA256 authenticated,
retries are idempotent, replay references persist across restarts, and every failure mode
fails closed (reject, never approve by default).</p>
<p><strong>Who it helps.</strong> Agent-commerce platforms, DAO and payment operations, and
anyone who lets an automated agent move money under conditions a human set in advance.</p>
<p><strong>Verify it yourself.</strong> Source, tests (15/15, including real proofs for every
trap type) and a sample task/response pair:
<a href="https://github.com/xcuz1999-beep/zkverify-gatekeeper-agent">github.com/xcuz1999-beep/zkverify-gatekeeper-agent</a>.
Gatekeeper verification key hash registered on zkVerify mainnet:
<code>0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0</code>.</p>
<p>Built for the zkVerify Agent Games (Proof Gatekeeper, Event 01) by zeo9.ai.</p>
</body></html>`;

const server = createServer((req, res) => {
  if (req.method === 'GET' && req.url.startsWith('/wildcard')) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(WILDCARD_PAGE);
    return;
  }
  if (req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, agent: 'zeo9-gatekeeper', events: ['proof-gatekeeper'] }));
    return;
  }
  if (req.method !== 'POST' || !req.url.startsWith('/agent')) {
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
    return;
  }
  const chunks = [];
  let size = 0;
  req.on('data', (c) => {
    size += c.length;
    if (size > 1_000_000) req.destroy();
    else chunks.push(c);
  });
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    if (!validSignature(raw, req.headers['x-agent-games-signature'])) {
      log('rejected request: bad signature');
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid signature' }));
      return;
    }
    let body;
    try {
      const envelope = JSON.parse(raw.toString('utf8'));
      if (envelope.type === 'agent-games.preflight.v1') {
        body = JSON.stringify({ ok: true, protocolVersion: 'v1' });
        log('preflight ok');
      } else if (envelope.type === 'agent-games.proof-gatekeeper.v1') {
        body = await handleTask(envelope);
      } else {
        log('unknown envelope type:', envelope.type);
        body = JSON.stringify({ decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' });
      }
    } catch (e) {
      log('handler error:', e.message?.slice(0, 160));
      body = JSON.stringify({ decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' });
    }
    res.writeHead(200, {
      'content-type': 'application/json',
      'x-agent-games-signature': hmac(body),
    });
    res.end(body);
  });
});

server.listen(PORT, () => log('zeo9-gatekeeper listening on port', PORT, '| taskId encoding:', ENCODING));
