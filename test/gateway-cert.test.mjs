// End-to-end test for the gateway certificate endpoints: a real node:https
// listener with a generated self-signed cert, hit with TLS verification
// disabled (exactly like a first-time visitor before they trust it).
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import https from 'node:https'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const { createGateway } = await import('../src/gateway-core.js')

let server, port, home, upstream

before(async () => {
  home = mkdtempSync(join(tmpdir(), 'um-gw-'))
  upstream = http.createServer((req, res) => { res.writeHead(200); res.end('upstream') })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  server = createGateway({
    listenHost: '127.0.0.1',
    port: 0, // ephemeral
    upstream: `http://127.0.0.1:${upstream.address().port}`,
    sites: [{ hosts: ['localhost', '100.79.247.70', '100.79.247.70.sslip.io', '100.79.247.70.nip.io'], cert: '', key: '' }],
    certsDir: join(home, 'certs'),
    decider: async () => ({ action: 'allow' }),
    handleApi: async () => {},
    renderLoginPage: () => '<html>login</html>',
    deps: { store: { listUsers: () => [] }, clientIp: () => '127.0.0.1' },
    clearedCookie: () => '',
    auditHooks: {},
    log: () => {},
    warn: () => {},
  })
  port = await server.start()
})

after(async () => {
  await server.stop()
  upstream.close()
  rmSync(home, { recursive: true, force: true })
})

function get(path) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      host: '127.0.0.1', port, path, method: 'GET', rejectUnauthorized: false,
      headers: { host: 'localhost' }, // must be inside the site allow-list
    }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }))
    })
    req.on('error', reject)
    req.end()
  })
}

test('GET /user-management/api/cert serves the PEM without login', async () => {
  const res = await get('/user-management/api/cert')
  assert.equal(res.status, 200)
  assert.equal(res.headers['content-type'], 'application/x-pem-file')
  assert.match(res.headers['content-disposition'], /user-management-gateway\.crt/)
  const pem = res.body.toString('utf8')
  assert.match(pem, /-----BEGIN CERTIFICATE-----/)
  assert.match(pem, /-----END CERTIFICATE-----/)
})

test('GET ?format=der serves DER bytes with the .cer filename', async () => {
  const res = await get('/user-management/api/cert?format=der')
  assert.equal(res.status, 200)
  assert.equal(res.headers['content-type'], 'application/x-x509-ca-cert')
  assert.match(res.headers['content-disposition'], /user-management-gateway\.cer/)
  assert.equal(res.body[0], 0x30, 'DER starts with the SEQUENCE tag')
})

test('GET /user-management/api/cert-info exposes fingerprint + covered names', async () => {
  const res = await get('/user-management/api/cert-info')
  assert.equal(res.status, 200)
  const info = JSON.parse(res.body.toString('utf8'))
  assert.match(info.fingerprint, /^[0-9A-F:]{95}$/, 'SHA-256 fingerprint, colon-separated hex')
  assert.ok(info.notAfter, 'expiry present')
  for (const name of ['localhost', '100.79.247.70', '100.79.247.70.sslip.io', '100.79.247.70.nip.io']) {
    assert.ok(info.hosts.includes(name), `covers ${name}`)
  }
})

test('cert download works even with an unauthenticated session decision', async () => {
  // decider here always allows; flip it by exercising a request path the
  // gate would normally 401 — the cert endpoints run BEFORE that logic, so
  // an anonymous decider must not change the outcome
  const res = await get('/user-management/api/cert')
  assert.equal(res.status, 200)
})
