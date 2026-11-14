# Wildcard entry — zeo9-gatekeeper, a proof-backed payment firewall

**Agent link:** https://github.com/xcuz1999-beep/zkverify-gatekeeper-agent
**Public endpoint:** https://<hf-space-host>/agent (health: `/`, explainer: `/wildcard`)
**Events:** Proof Gatekeeper (Event 01) + this Wildcard submission

## Use case

**Problem.** AI agents increasingly initiate payments. A zero-knowledge proof
that verifies only proves a statement was proven — it does not prove the
payment *should* happen. In the Agent Games' own trap taxonomy, a perfectly
valid proof can still carry a substituted verification key (~13% of tasks), a
replayed proof reference (~11%), a below-threshold balance (~8%), an expired
condition (~6%), a wrong recipient (~6%), or an over-cap amount (~6%).
An agent that approves on "proof verified" alone loses money in roughly half
of all adversarial cases. This is the generic failure mode of agent commerce,
not just of this game.

**What it does.** zeo9-gatekeeper is a deterministic payment firewall between
a payment request and its approval:

1. Authenticate the request (HMAC-SHA256 over the raw body) before parsing.
2. Check every field against the registered condition in a fixed order —
   replay, verification key, threshold, expiry, recipient, amount cap —
   where the first failure names the rejection reason.
3. Return the decision together with a Groth16 proof *of the decision
   itself*, generated locally with the official gatekeeper circuit. The
   circuit refuses to produce a proof for a wrong decision, so the evidence
   is not a claim: anyone can re-verify it against the verification key
   registered on zkVerify mainnet
   (`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`).
4. Persist the seen-set of approved proof references and cache responses
   per task id, so retries are idempotent and replays stay rejected across
   restarts. Every error path fails closed: reject, never approve by default.

**Who it helps.** Agent-commerce platforms settling agent-to-agent payments,
DAO/payment operations with standing payment conditions, and any team that
lets an automated agent move funds under rules a human fixed in advance.

## Build context

- **Deterministic code decides; no language model is in the decision path.**
  The final safety rules are pure functions (`checks.mjs`) — auditable,
  unit-testable, and identical on every retry.
- **Check order mirrors loss asymmetry.** Approving a trap is the expensive
  error, so replay and key-substitution checks run first; threshold, expiry,
  recipient and cap follow in the order the conditions are documented.
- **Proofs are generated locally** with snarkjs from the official circuit
  artifacts (SHA-256 of the downloaded artifacts matches the independently
  mirrored checksums). No third party custodies the decision or the evidence.
- **The one deliberate omission:** `PROOF_REUSED` responses carry no proof.
  Reuse is agent-side state, not a circuit property — the honest design is
  to say so rather than attach an irrelevant proof.
- **Tested end to end:** `node test.mjs` boots the real server and replays
  preflight plus every documented trap type — 15/15 checks pass, including
  local verification of each generated proof against the official VK.
  `samples/` holds a real task/response pair judges can re-verify offline.

## zkVerify claim

Every decision this agent returns in the Proof Gatekeeper arena is
accompanied by a Groth16 proof whose verification key is registered on
zkVerify mainnet (vk hash above). The platform independently re-verifies
each proof; the same verification can be reproduced locally with
`npx snarkjs groth16 verify circuits/gatekeeper_vk.json <public_signals> <proof>`
using the artifacts linked from the repository README.
