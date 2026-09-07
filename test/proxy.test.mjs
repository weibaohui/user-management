// Unit tests for the gateway reverse proxy's dsh-client-connection token-gate
// adaptation: index requests mint a loopback cookie from the dsh launchToken
// and inject it upstream; non-index paths proxy plain; with no launchToken
// (dsh 0.1.1-rc.2, no BrowserAuth) the proxy falls through to passthrough.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'

const { createProxy } = await import('../src/proxy.js')

// Mock upstream that mimics dsh-client-connection's authorizeIndex gate:
//   GET /?token=T   -> 303 Set-Cookie: dshcookie=abc + Location: /
//   GET / + cookie  -> 200 index.html
//   GET / no cookie -> 401 "dsh web authentication required"
//   GET /api/*      -> 200 (non-index, not gated)
let upstream, upstreamPort

before(async () => {
  upstream = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://upstream.invalid')
    // Token exchange: stamp the browser cookie and redirect to clean /.
    if ((url.pathname === '/' || url.pathname === '/index.html') && url.searchParams.get('token')) {
      res.writeHead(303, { 'set-cookie': ['dshcookie=abc; Path=/'], location: '/' })
      res.end()
      return
    }
    // Index: gated by the authority-bound cookie.
    if (url.pathname === '/' || url.pathname === '/index.html') {
      if ((req.headers.cookie || '').includes('dshcookie=abc')) {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
        res.end('<html><body>index</body></html>')
      } else {
        res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
        res.end('dsh web authentication required; reopen the URL printed by dsh web.\n')
      }
      return
    }
    // Everything else (e.g. /api) is not gated by authorizeIndex.
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' })
    res.end('api')
  })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  upstreamPort = upstream.address().port
})

after(async () => {
  await new Promise((resolve) => upstream.close(resolve))
})

// Drive a proxy: spin a one-shot http server whose handler is proxy.handleRequest,
// issue one client GET, then close. Returns { status, headers, body }.
function get(proxy, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      proxy.handleRequest(req, res)
    })
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port
      const req = http.request(
        { host: '127.0.0.1', port, path, method: 'GET', headers },
        (res) => {
          const chunks = []
          res.on('data', (c) => chunks.push(c))
          res.on('end', () => {
            server.close()
            resolve({
              status: res.statusCode,
              headers: res.headers,
              body: Buffer.concat(chunks).toString(),
            })
          })
        },
      )
      req.on('error', (err) => {
        server.close()
        reject(err)
      })
      req.end()
    })
  })
}

test('index request mints a cookie from launchToken and serves 200 index', async () => {
  const proxy = createProxy(`http://127.0.0.1:${upstreamPort}`, () => 'LAUNCH')
  const res = await get(proxy, '/')
  assert.equal(res.status, 200, `expected 200, got ${res.status}: ${res.body}`)
  assert.match(res.body, /index/)
  assert.ok(proxy.getDshCookie(), 'a loopback cookie was minted from the launchToken')
  // The upstream's Set-Cookie (loopbound) must NOT leak to the public client.
  assert.equal(res.headers['set-cookie'], undefined, 'loopback cookie not forwarded to the browser')
  proxy.close()
})

test('non-index path proxies plain — no token gate, no cookie minted', async () => {
  const proxy = createProxy(`http://127.0.0.1:${upstreamPort}`, () => 'LAUNCH')
  const res = await get(proxy, '/api/foo')
  assert.equal(res.status, 200)
  assert.equal(res.body, 'api')
  assert.equal(proxy.getDshCookie(), null, 'no cookie minted for non-index paths')
  proxy.close()
})

test('no launchToken (dsh 0.1.1-rc.2) falls through — index reaches upstream ungated', async () => {
  const proxy = createProxy(`http://127.0.0.1:${upstreamPort}`, () => null)
  const res = await get(proxy, '/')
  // Upstream has the gate, so without an injected cookie it answers 401 —
  // proving the proxy did NOT mint/inject (passthrough behaviour on 0.1.1-rc.2
  // where there is no gate, this would be 200).
  assert.equal(res.status, 401)
  assert.equal(proxy.getDshCookie(), null)
  proxy.close()
})

test('index with a query string still counts as index and gets the cookie', async () => {
  const proxy = createProxy(`http://127.0.0.1:${upstreamPort}`, () => 'LAUNCH')
  const res = await get(proxy, '/?foo=bar')
  assert.equal(res.status, 200, `expected 200, got ${res.status}`)
  assert.ok(proxy.getDshCookie(), 'cookie minted for index with query')
  proxy.close()
})
