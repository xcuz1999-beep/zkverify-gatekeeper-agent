# zeo9-gatekeeper — Proof Gatekeeper agent

Agent for **Proof Gatekeeper** (Event 01) of the zkVerify Agent Games,
competing under the handle **zeo9.ai**.

The platform POSTs signed tasks to this endpoint; the agent decides
APPROVE or REJECT deterministically and answers with a Groth16 proof
generated locally from the official gatekeeper circuit.

## How it works

- `server.mjs` — HTTPS transport. Verifies `x-agent-games-signature`
  (HMAC-SHA256 over the raw body) before parsing, routes preflight and
  task envelopes, signs every response. Responses are cached per
  `task_id` (platform retries are idempotency keys); the seen-set of
  approved proof references persists on disk across restarts.
- `checks.mjs` — the decision table, first failure names the reason:
  proof reuse → VK substitution → threshold → expiry → recipient →
  amount overflow. Fail closed on malformed input. No model decides.
- `prove.mjs` — field encoding (values reduced mod the BN254 scalar
  field; `task_id` encoding switchable via `TASK_ID_ENCODING`) and
  snarkjs proving/verification with the official circuit artifacts.

Scoring awareness: a wrong APPROVE costs more than a wrong REJECT, a
missing/invalid proof on a provable task costs extra, and
`PROOF_REUSED` responses carry no proof (reuse is not in the circuit).

## Setup

```sh
# official circuit artifacts (checksums published on the /build page)
curl -O https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -O https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
mv gatekeeper.wasm gatekeeper_final.zkey circuits/
npx snarkjs zkey export verificationkey circuits/gatekeeper_final.zkey circuits/gatekeeper_vk.json

npm install
cp .env.example .env   # set AGENT_GAMES_HMAC_SECRET from the dashboard (Rotate Secret)
npm test               # boots the server and replays every trap type
node server.mjs        # production
```

## Tests

`node test.mjs` — 15 checks: health, preflight shape + signature,
bad-signature rejection, the valid case (proof generated and verified
against the official VK), retry idempotency, proof reuse, and all five
remaining trap types with proofs.
