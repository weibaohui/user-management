// TOTP two-step verification: RFC 6238 vectors for the crypto core, the
// store enrollment lifecycle, and the API login flow (otpRequired handshake,
// replay guard, brute-force lockout, admin reset).
import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const totp = require('../src/totp.js')
const { createStore } = require('../src/store.js')
const plugin = require('../src/index.js')
const { handleApi, createOtpGuard, totpQrSvg } = plugin.__internals

// ── crypto core ─────────────────────────────────────────────────────────────

test('RFC 6238 Appendix B official SHA-1 test vectors (6-digit truncation)', () => {
  // ASCII "12345678901234567890" → base32
  const secret = totp.base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
  const vectors = [
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
    [20000000000, '353130'],
  ]
  for (const [unixSeconds, expected] of vectors) {
    assert.equal(totp.totpAt(secret, unixSeconds), expected, `t=${unixSeconds}`)
  }
})

test('base32 roundtrip and tolerant decode', () => {
  const buf = Buffer.from('hello totp world 0123', 'utf8')
  const encoded = totp.base32Encode(buf)
  assert.match(encoded, /^[A-Z2-7]+$/, 'RFC 4648 alphabet (authenticator manual-entry format)')
  assert.ok(totp.base32Decode(encoded).equals(buf), 'roundtrip')
  assert.ok(totp.base32Decode(encoded.toLowerCase()).equals(buf), 'case-insensitive')
  assert.ok(totp.base32Decode(encoded.replace(/(.{4)/g, '$1 ')).equals(buf), 'whitespace ignored')
  assert.equal(totp.base32Decode('1!@#').length, 0, 'invalid input decodes to empty')
  assert.equal(totp.generateSecret().length, 32, '160-bit secret = 32 base32 chars')
  assert.notEqual(totp.generateSecret(), totp.generateSecret())
})

test('verifyTotp accepts ±1 step, rejects wrong/non-numeric codes and replays', () => {
  const secret = totp.generateSecret()
  const nowMs = 1_750_000_000_000
  const step = Math.floor(nowMs / 1000 / totp.OTP_STEP_SECONDS)
  const codeAt = (c) => totp.hotp(totp.base32Decode(secret), c)

  assert.deepEqual(totp.verifyTotp(secret, codeAt(step), { nowMs }), { ok: true, counter: step })
  assert.deepEqual(totp.verifyTotp(secret, codeAt(step - 1), { nowMs }), { ok: true, counter: step - 1 }, 'previous step (clock drift)')
  assert.deepEqual(totp.verifyTotp(secret, codeAt(step + 1), { nowMs }), { ok: true, counter: step + 1 }, 'next step')
  assert.equal(totp.verifyTotp(secret, codeAt(step + 2), { nowMs }).ok, false, 'outside the window')
  const windowCodes = new Set([codeAt(step - 1), codeAt(step), codeAt(step + 1)])
  const sureWrong = windowCodes.has('000000') ? '000001' : '000000'
  assert.equal(totp.verifyTotp(secret, sureWrong, { nowMs }).ok, false, 'wrong code')
  assert.equal(totp.verifyTotp(secret, '12345', { nowMs }).ok, false, 'not 6 digits')
  assert.equal(totp.verifyTotp(secret, 'abcdef', { nowMs }).ok, false, 'non-numeric')
  assert.equal(totp.verifyTotp(secret, '', { nowMs }).ok, false, 'empty')
  assert.equal(totp.verifyTotp('BAD@#', '123456', { nowMs }).ok, false, 'undecodable secret')
  // single use: counters ≤ lastCounter are refused
  assert.equal(totp.verifyTotp(secret, codeAt(step), { nowMs, lastCounter: step }).ok, false, 'exact replay')
  assert.equal(totp.verifyTotp(secret, codeAt(step - 1), { nowMs, lastCounter: step }).ok, false, 'older step replay')
  assert.ok(totp.verifyTotp(secret, codeAt(step + 1), { nowMs, lastCounter: step }).ok, 'newer step still valid')
})

test('otpauth URI carries secret/issuer/algorithm and is QR-encodable', () => {
  const uri = totp.otpauthUri({ username: 'boss', secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' })
  assert.ok(uri.startsWith('otpauth://totp/DSH%3Aboss?'), uri)
  assert.ok(uri.includes('secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'))
  assert.ok(uri.includes('issuer=DSH') && uri.includes('algorithm=SHA1') && uri.includes('digits=6') && uri.includes('period=30'))
  const svg = totpQrSvg(uri)
  assert.ok(svg.startsWith('<svg') && svg.endsWith('</svg>'), 'setup payload renders as an SVG QR')
})

// ── store lifecycle ─────────────────────────────────────────────────────────

let home, store

beforeEach(async () => {
  home = mkdtempSync(join(tmpdir(), 'um-totp-'))
  store = createStore({ home })
  await store.load()
})

afterEach(() => {
  rmSync(home, { recursive: true, force: true })
})

/** Current valid window codes for a secret — used to pick sure-wrong codes. */
function windowCodes(secret, nowMs = Date.now()) {
  const step = Math.floor(nowMs / 1000 / totp.OTP_STEP_SECONDS)
  const buf = totp.base32Decode(secret)
  return [step - 1, step, step + 1].map((c) => totp.hotp(buf, c))
}

function wrongCode(secret) {
  const taken = new Set(windowCodes(secret))
  if (!taken.has('000000')) return '000000'
  for (let i = 1; i < 1000; i += 1) {
    const candidate = String(i).padStart(6, '0')
    if (!taken.has(candidate)) return candidate
  }
  throw new Error('no wrong code found')
}

test('enrollment: setup → wrong code stays pending → right code enables', async () => {
  await store.createUser({ username: 'alice', password: 'secret1' })
  const user = store.findUserByUsername('alice')
  assert.equal(store.publicUser(user).totpEnabled, false)

  const { secret } = await store.startTotpSetup(user)
  assert.match(secret, /^[A-Z2-7]{32}$/)
  assert.equal(store.publicUser(user).totpEnabled, false, 'pending secret is not enabled')

  assert.equal(await store.activateTotp(user, wrongCode(secret)), false, 'wrong code does not enable')
  assert.equal(store.publicUser(user).totpEnabled, false)

  const code = totp.hotp(totp.base32Decode(secret), Math.floor(Date.now() / 1000 / totp.OTP_STEP_SECONDS))
  assert.equal(await store.activateTotp(user, code), true)
  assert.equal(store.publicUser(user).totpEnabled, true)
  const raw = store.__state().users[0]
  assert.ok(raw.totpSecret && !raw.totpPendingSecret, 'pending promoted, no pending residue')

  await assert.rejects(() => store.startTotpSetup(user), (e) => e.code === 'totp_enabled', 're-setup refused while enabled')
})

test('verifyLoginOtp: not-enabled passthrough, single-use replay guard persisted', async () => {
  await store.createUser({ username: 'bob', password: 'secret1' })
  const plain = store.findUserByUsername('bob')
  assert.deepEqual(await store.verifyLoginOtp(plain, '123456'), { ok: false, notEnabled: true })

  const { secret } = await store.startTotpSetup(plain)
  const codeFor = (offsetSteps) => totp.hotp(totp.base32Decode(secret), Math.floor(Date.now() / 1000 / totp.OTP_STEP_SECONDS) + offsetSteps)
  assert.equal(await store.activateTotp(plain, codeFor(0)), true)

  const user = store.findUserByUsername('bob')
  const code = codeFor(1) // captured once: a 30s-step boundary must not turn the replay into a fresh valid code
  const first = await store.verifyLoginOtp(user, code)
  assert.equal(first.ok, true, 'next-step code accepted at login')
  assert.equal((await store.verifyLoginOtp(user, code)).ok, false, 'same code replayed → rejected')
  assert.ok(store.__state().users[0].totpLastCounter > 0, 'matched counter persisted')
})

test('disableTotp clears every field; admin reset shares the path', async () => {
  await store.createUser({ username: 'carol', password: 'secret1' })
  const user = store.findUserByUsername('carol')
  const { secret } = await store.startTotpSetup(user)
  const code = totp.hotp(totp.base32Decode(secret), Math.floor(Date.now() / 1000 / totp.OTP_STEP_SECONDS))
  await store.activateTotp(user, code)

  await store.disableTotp(user)
  const raw = store.__state().users[0]
  assert.ok(!raw.totpSecret && !raw.totpPendingSecret && !raw.totpLastCounter && !raw.totpEnabledAt, 'all TOTP fields gone')
  assert.equal(store.publicUser(user).totpEnabled, false)
  await assert.rejects(() => store.disableTotp(user), (e) => e.code === 'totp_not_enabled')
})

test('otpGuard: consecutive failures lock, even valid codes wait, reset clears', () => {
  let clock = 1000
  const guard = createOtpGuard({ limit: 3, lockoutMs: 10_000, now: () => clock })
  assert.equal(guard.locked('alice'), 0)
  guard.fail('alice')
  guard.fail('ALICE') // same key, case-insensitive
  assert.equal(guard.locked('alice'), 0, 'under the limit')
  guard.fail('alice')
  assert.equal(guard.locked('alice'), 10_000, 'locked at the limit')
  clock += 9_999
  assert.equal(guard.locked('alice'), 1, 'still locked')
  clock += 2
  assert.equal(guard.locked('alice'), 0, 'lockout expired')
  guard.fail('alice')
  guard.fail('alice')
  guard.fail('alice')
  assert.equal(guard.locked('alice'), 10_000, 're-locked after a fresh streak')
  guard.reset('alice')
  assert.equal(guard.locked('alice'), 0)
  assert.equal(guard.locked('nobody'), 0)
})

// ── API login flow over a real http server ──────────────────────────────────

let server, port, deps

beforeEach(async () => {
  deps = { store, clientIp: () => '203.0.113.9' }
  server = http.createServer((req, res) => {
    handleApi(req, res, deps).catch((error) => {
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: String(error && error.message) }))
      } else {
        res.end()
      }
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  port = server.address().port
})

afterEach(() => {
  server.close()
  server.closeAllConnections()
})

function call(path, { method = 'GET', body, cookie } = {}) {
  const headers = {}
  if (body !== undefined) headers['content-type'] = 'application/json'
  if (cookie) headers.cookie = cookie
  return fetch(`http://127.0.0.1:${port}/user-management/api${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  }).then(async (res) => ({ status: res.status, data: await res.json().catch(() => ({})), headers: res.headers }))
}

function cookieOf(res) {
  const raw = res.headers.get('set-cookie') || ''
  const match = /um_session=([^;]*)/.exec(raw)
  return match ? `um_session=${match[1]}` : null
}

/** Enroll a logged-in user end-to-end; returns the secret. */
async function enroll(cookie) {
  const setup = await call('/me/totp/setup', { method: 'POST', cookie })
  assert.equal(setup.status, 200)
  assert.ok(setup.data.secret && setup.data.otpauth && setup.data.qrSvg.startsWith('<svg'))
  const code = totp.hotp(totp.base32Decode(setup.data.secret), Math.floor(Date.now() / 1000 / totp.OTP_STEP_SECONDS))
  const activate = await call('/me/totp/activate', { method: 'POST', body: { code }, cookie })
  assert.equal(activate.status, 200, 'activation with a live code')
  return setup.data.secret
}

test('login demands the OTP only after the password is correct; replay dies; disable restores', async () => {
  const reg = await call('/register', { method: 'POST', body: { username: 'dana', password: 'secret1' } })
  const cookie = cookieOf(reg)
  const secret = await enroll(cookie)

  // enrollment shows up in the session payload + the activity ledger
  assert.equal((await call('/session', { cookie })).data.user.totpEnabled, true)
  const ledger = (await call('/activity', { cookie })).data.entries
  assert.ok(ledger.some((e) => e.type === 'totp_enabled'), 'totp_enabled logged')

  // password-only login → 401 + otpRequired (no session cookie leaked)
  const noOtp = await call('/login', { method: 'POST', body: { username: 'dana', password: 'secret1' } })
  assert.equal(noOtp.status, 401)
  assert.equal(noOtp.data.otpRequired, true)
  assert.equal(cookieOf(noOtp), null)
  // wrong password stays a plain invalid (never hints at TOTP)
  const wrongPwd = await call('/login', { method: 'POST', body: { username: 'dana', password: 'nope' } })
  assert.equal(wrongPwd.status, 401)
  assert.equal(wrongPwd.data.otpRequired, undefined)

  const codeFor = (offsetSteps) => totp.hotp(totp.base32Decode(secret), Math.floor(Date.now() / 1000 / totp.OTP_STEP_SECONDS) + offsetSteps)
  const bad = await call('/login', { method: 'POST', body: { username: 'dana', password: 'secret1', otp: wrongCode(secret) } })
  assert.equal(bad.status, 401)
  assert.equal(bad.data.otpRequired, true)

  const code = codeFor(1) // captured once so the replay below stays the same code across step boundaries
  const good = await call('/login', { method: 'POST', body: { username: 'dana', password: 'secret1', otp: code } })
  assert.equal(good.status, 200, 'next-step code signs in')
  assert.ok(cookieOf(good))

  const replay = await call('/login', { method: 'POST', body: { username: 'dana', password: 'secret1', otp: code } })
  assert.equal(replay.status, 401, 'the same code cannot sign in twice')

  // disable requires the login password
  const badDisable = await call('/me/totp/disable', { method: 'POST', body: { password: 'nope' }, cookie: cookieOf(good) })
  assert.equal(badDisable.status, 400)
  const disabled = await call('/me/totp/disable', { method: 'POST', body: { password: 'secret1' }, cookie: cookieOf(good) })
  assert.equal(disabled.status, 200)
  assert.equal((await call('/session', { cookie: cookieOf(good) })).data.user.totpEnabled, false)
  assert.equal((await call('/login', { method: 'POST', body: { username: 'dana', password: 'secret1' } })).status, 200, 'password-only login works again')
})

test('setup/activate endpoints refuse anonymous and double-setup; activation validates codes', async () => {
  assert.equal((await call('/me/totp/setup', { method: 'POST' })).status, 401)
  assert.equal((await call('/me/totp/activate', { method: 'POST', body: { code: '123456' } })).status, 401)
  assert.equal((await call('/me/totp/disable', { method: 'POST', body: { password: 'x' } })).status, 401)

  const reg = await call('/register', { method: 'POST', body: { username: 'erin', password: 'secret1' } })
  const cookie = cookieOf(reg)
  const first = await call('/me/totp/setup', { method: 'POST', cookie })
  assert.equal(first.status, 200)
  assert.equal((await call('/me/totp/activate', { method: 'POST', body: { code: wrongCode(first.data.secret) }, cookie })).status, 400, 'wrong code → 400, still not enabled')
  assert.equal((await call('/session', { cookie })).data.user.totpEnabled, false)
  const second = await call('/me/totp/setup', { method: 'POST', cookie })
  assert.equal(second.status, 200, 're-setup before activation regenerates the pending secret')
  assert.notEqual(second.data.secret, first.data.secret)
  const code = totp.hotp(totp.base32Decode(second.data.secret), Math.floor(Date.now() / 1000 / totp.OTP_STEP_SECONDS))
  assert.equal((await call('/me/totp/activate', { method: 'POST', body: { code }, cookie })).status, 200)
  const reSetup = await call('/me/totp/setup', { method: 'POST', cookie })
  assert.equal(reSetup.status, 409, 'setup refused while enabled')
})

test('admin reset-totp recovers a lost device; plain users cannot; guard locks brute force', async () => {
  const boss = await call('/register', { method: 'POST', body: { username: 'boss', password: 'secret1' } })
  const adminCookie = cookieOf(boss)
  const member = await call('/register', { method: 'POST', body: { username: 'frank', password: 'secret1' } })
  const frankCookie = cookieOf(member)
  const frankId = member.data.user.id
  await enroll(frankCookie)

  assert.equal((await call(`/users/${frankId}/reset-totp`, { method: 'POST', cookie: frankCookie })).status, 403, 'self-service reset is admin-only')
  const reset = await call(`/users/${frankId}/reset-totp`, { method: 'POST', cookie: adminCookie })
  assert.equal(reset.status, 200)
  assert.equal(reset.data.user.totpEnabled, false)
  assert.equal((await call(`/users/${frankId}/reset-totp`, { method: 'POST', cookie: adminCookie })).status, 409, 'resetting an unenrolled account conflicts')
  assert.equal((await call('/login', { method: 'POST', body: { username: 'frank', password: 'secret1' } })).status, 200, 'password-only login after admin reset')
  // 未开启两步验证的用户：动态码字段选填，填了也会被服务端忽略
  const withIgnoredOtp = await call('/login', { method: 'POST', body: { username: 'frank', password: 'secret1', otp: '123456' } })
  assert.equal(withIgnoredOtp.status, 200, 'stale/stray otp on a non-enrolled account is ignored')
  assert.equal(withIgnoredOtp.data.otpRequired, undefined)

  // brute-force lockout: OTP_FAIL_LIMIT consecutive bad codes → even the
  // valid code is refused with 429 until the lockout lapses
  const secret = await enroll(adminCookie)
  for (let i = 0; i < 5; i += 1) {
    const attempt = await call('/login', { method: 'POST', body: { username: 'boss', password: 'secret1', otp: wrongCode(secret) } })
    assert.equal(attempt.status, 401)
  }
  const valid = totp.hotp(totp.base32Decode(secret), Math.floor(Date.now() / 1000 / totp.OTP_STEP_SECONDS) + 1)
  const locked = await call('/login', { method: 'POST', body: { username: 'boss', password: 'secret1', otp: valid } })
  assert.equal(locked.status, 429, 'valid code refused while locked')
  assert.equal(locked.data.otpRequired, true)
  const other = await call('/login', { method: 'POST', body: { username: 'frank', password: 'secret1' } })
  assert.equal(other.status, 200, 'lockout is per-account, not global')

  const adminLedger = (await call('/activity?limit=50', { cookie: adminCookie })).data.entries
  assert.ok(adminLedger.some((e) => e.type === 'totp_reset'), 'totp_reset in the admin ledger')
  assert.ok(adminLedger.filter((e) => e.type === 'login_failed' && String(e.detail).includes('totp')).length >= 5, 'OTP failures are attributed in the ledger')
})
