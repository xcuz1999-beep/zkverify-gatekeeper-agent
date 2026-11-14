// Vercel serverless entry — wraps the exact same request handler as
// server.mjs (single source of truth). State (seen-set + response cache)
// is kept under /tmp: it survives while the function instance stays warm
// and resets on cold starts.
process.env.DATA_DIR = process.env.DATA_DIR || '/tmp/zkv-gatekeeper-data';

let cached = null;
export default async function vercelHandler(req, res) {
  if (!cached) {
    const mod = await import('../server.mjs');
    cached = mod.handler;
  }
  return cached(req, res);
}

export const config = { api: { bodyParser: false } };
