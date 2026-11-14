// Zero-dependency probe: proves a new deployment is live and the
// functions platform itself works, independent of the agent code.
export default function ping(req, res) {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ pong: true, marker: 'diag2' }));
}
