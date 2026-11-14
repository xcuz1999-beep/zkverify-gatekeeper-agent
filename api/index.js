// Vercel serverless entry — wraps the exact same request handler as
// server.mjs (single source of truth). State (seen-set + response cache)
// is kept under /tmp: it survives while the function instance stays warm
// and resets on cold starts.
process.env.DATA_DIR = process.env.DATA_DIR || '/tmp/zkv-gatekeeper-data';

let cached = null;
let loadError = null;
export default async function vercelHandler(req, res) {
  if (!cached && !loadError) {
    try {
      const mod = await import('../server.mjs');
      cached = mod.handler;
    } catch (e) {
      loadError = e;
    }
  }
  if (loadError) {
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      error: 'module load failed',
      message: String((loadError && loadError.message) || loadError),
      stack: String((loadError && loadError.stack) || '').split('\n').slice(0, 8),
    }));
    return;
  }
  try {
    return await cached(req, res);
  } catch (e) {
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'handler failed', message: String((e && e.message) || e) }));
  }
}

export const config = { api: { bodyParser: false } };
