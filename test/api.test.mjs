// API tests: the full permission matrix over a real http server.
import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { createStore } = require('../src/store.js')
const { SESSION_COOKIE, parseCookies, isAuditableRequest } = require('../src/gate.js')
const plugin = require('../src/index.js')
const { handleApi } = plugin.__internals

let home, store, server, port, deps

// Replicates the gateway's wireAudit: on response completion, record the
// operation in the audit ledger (the gateway does this in production; the
// bare-http test server has no gate, so handleApi's own 401-anonymous covers
// access control and this wrapper covers the audit ledger).
function withAudit(handler, deps) {
  return async (req, res) => {
    const cookies = parseCookies(req.headers && req.headers.cookie)
    const session = await deps.store.resolveSession(cookies[SESSION_COOKIE])
    let path = '/'
    try { path = new URL(req.url || '/', 'http://dsh.local').pathname } catch { /* keep default */ }
    if (isAuditableRequest((req.method || 'GET').toUpperCase(), req.headers && req.headers.accept, path)) {
      res.on('finish', () => {
        deps.store.appendAudit({
          type: 'api',
          username: session ? session.user.username : null,
          userId: session ? session.user.id : null,
          ip: deps.clientIp(req),
          method: (req.method || 'GET').toUpperCase(),
          path,
          status: res.statusCode,
        }).catch(() => {})
      })
    }
    return handler(req, res, deps)
  }
}

beforeEach(async () => {
  home = mkdtempSync(join(tmpdir(), 'um-api-'))
  store = createStore({ home })
  await store.load()
  deps = { store, clientIp: () => '127.0.0.1' }
  server = http.createServer((req, res) => {
    withAudit(handleApi, deps)(req, res).catch((error) => {
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
  rmSync(home, { recursive: true, force: true })
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
  const match = new RegExp(`${SESSION_COOKIE}=([^;]*)`).exec(raw)
  return match ? `${SESSION_COOKIE}=${match[1]}` : null
}

test('permission matrix: anonymous / plain user / admin across every endpoint', async () => {
  // ── anonymous ──
  assert.equal((await call('/session')).data.user, null)
  assert.equal((await call('/users')).status, 401)
  assert.equal((await call('/activity')).status, 401)
  assert.equal((await call('/me/password', { method: 'POST', body: {} })).status, 401)

  // ── first registration → admin, second → plain user ──
  const regA = await call('/register', { method: 'POST', body: { username: 'boss', password: 'secret1' } })
  assert.equal(regA.status, 200)
  assert.equal(regA.data.user.role, 'admin')
  const adminCookie = cookieOf(regA)
  assert.ok(adminCookie)

  const regB = await call('/register', { method: 'POST', body: { username: 'alice', password: 'secret1' } })
  assert.equal(regB.data.user.role, 'user')
  const userCookie = cookieOf(regB)
  const alice = regB.data.user

  // duplicate register
  assert.equal((await call('/register', { method: 'POST', body: { username: 'ALICE', password: 'secret1' } })).status, 400)
  // bad username / short password
  assert.equal((await call('/register', { method: 'POST', body: { username: 'x!', password: 'secret1' } })).status, 400)
  assert.equal((await call('/register', { method: 'POST', body: { username: 'carol', password: '12345' } })).status, 400)

  // ── session echo ──
  assert.equal((await call('/session', { cookie: adminCookie })).data.user.username, 'boss')
  assert.equal((await call('/session', { cookie: userCookie })).data.user.username, 'alice')
  assert.equal((await call('/session', { cookie: `${SESSION_COOKIE}=forged` })).data.user, null)

  // ── login ──
  const bad = await call('/login', { method: 'POST', body: { username: 'boss', password: 'nope' } })
  assert.equal(bad.status, 401)
  const good = await call('/login', { method: 'POST', body: { username: 'BOSS', password: 'secret1' } })
  assert.equal(good.status, 200)
  assert.ok(cookieOf(good))

  // ── users list scoping ──
  const adminView = await call('/users', { cookie: adminCookie })
  assert.equal(adminView.data.users.length, 2)
  const userView = await call('/users', { cookie: userCookie })
  assert.deepEqual(userView.data.users.map((u) => u.username), ['alice'])
  // no hash material ever leaks
  assert.deepEqual(Object.keys(userView.data.users[0]).sort(), ['createdAt', 'disabled', 'id', 'lastLoginAt', 'role', 'username'])

  // ── admin actions are admin-only ──
  assert.equal((await call(`/users/${alice.id}/reset-password`, { method: 'POST', cookie: userCookie })).status, 403)
  assert.equal((await call(`/users/${alice.id}/role`, { method: 'POST', body: { role: 'admin' }, cookie: userCookie })).status, 403)
  assert.equal((await call(`/users/${alice.id}`, { method: 'DELETE', cookie: userCookie })).status, 403)
  assert.equal((await call(`/users/${alice.id}`, { method: 'DELETE' })).status, 401) // the gate denies anonymous before role checks

  // ── reset password: temp password works, old sessions die ──
  const oldAliceSession = await call('/login', { method: 'POST', body: { username: 'alice', password: 'secret1' } })
  const oldAliceCookie = cookieOf(oldAliceSession)
  const reset = await call(`/users/${alice.id}/reset-password`, { method: 'POST', cookie: adminCookie })
  assert.equal(reset.status, 200)
  assert.match(reset.data.tempPassword, /^[A-Za-z0-9_-]{4}-[A-Za-z0-9_-]{4}-[A-Za-z0-9_-]{4}$/)
  assert.equal((await call('/session', { cookie: oldAliceCookie })).data.user, null, 'pre-reset session is killed')
  const withTemp = await call('/login', { method: 'POST', body: { username: 'alice', password: reset.data.tempPassword } })
  assert.equal(withTemp.status, 200, 'temp password logs in')
  assert.equal((await call('/login', { method: 'POST', body: { username: 'alice', password: 'secret1' } })).status, 401, 'old password dead')

  // ── role change: self-change blocked, target re-login enforced ──
  assert.equal((await call(`/users/${regA.data.user.id}/role`, { method: 'POST', body: { role: 'user' }, cookie: adminCookie })).status, 403)
  const promote = await call(`/users/${alice.id}/role`, { method: 'POST', body: { role: 'admin' }, cookie: adminCookie })
  assert.equal(promote.status, 200)
  assert.equal(promote.data.user.role, 'admin')
  const tempCookie = cookieOf(withTemp)
  assert.equal((await call('/session', { cookie: tempCookie })).data.user, null, 'promoted user sessions dropped')

  // ── delete: self-delete blocked, last-admin handled at store level ──
  assert.equal((await call(`/users/${regA.data.user.id}`, { method: 'DELETE', cookie: adminCookie })).status, 403)
  assert.equal((await call(`/users/${alice.id}`, { method: 'DELETE', cookie: adminCookie })).status, 200)
  assert.equal((await call('/users', { cookie: adminCookie })).data.users.length, 1)
  assert.equal((await call(`/users/${alice.id}`, { method: 'DELETE', cookie: adminCookie })).status, 404)

  // ── password self-service ──
  const regC = await call('/register', { method: 'POST', body: { username: 'carol', password: 'secret1' } })
  const carolCookie = cookieOf(regC)
  const carolExtra = await call('/login', { method: 'POST', body: { username: 'carol', password: 'secret1' } })
  const carolExtraCookie = cookieOf(carolExtra)
  const wrongOld = await call('/me/password', { method: 'POST', body: { oldPassword: 'nope', newPassword: 'newpass1' }, cookie: carolCookie })
  assert.equal(wrongOld.status, 400)
  const changed = await call('/me/password', { method: 'POST', body: { oldPassword: 'secret1', newPassword: 'newpass1' }, cookie: carolCookie })
  assert.equal(changed.status, 200)
  assert.equal((await call('/session', { cookie: carolExtraCookie })).data.user, null, 'other sessions die on password change')
  assert.equal((await call('/session', { cookie: carolCookie })).data.user.username, 'carol', 'current session survives')
  assert.equal((await call('/login', { method: 'POST', body: { username: 'carol', password: 'newpass1' } })).status, 200)

  // ── activity visibility ──
  const adminLog = await call('/activity?limit=100', { cookie: adminCookie })
  const types = new Set(adminLog.data.entries.map((e) => e.type))
  for (const expected of ['register', 'login', 'login_failed', 'reset_password', 'role_change', 'delete_user', 'password_change']) {
    assert.ok(types.has(expected), `admin sees ${expected}`)
  }
  const userLog = await call('/activity?limit=100', { cookie: carolCookie })
  for (const entry of userLog.data.entries) {
    assert.equal(entry.userId, regC.data.user.id, 'plain users only see their own entries')
    assert.ok(['login', 'login_failed', 'logout', 'password_change'].includes(entry.type), `plain users never see ${entry.type}`)
  }

  // ── audit ledger: admin-only, records gated API actions ──
  await new Promise((r) => setTimeout(r, 50)) // let the async append chain drain
  assert.equal((await call('/audit')).status, 401)
  assert.equal((await call('/audit', { cookie: carolCookie })).status, 403)
  const audit = await call('/audit?limit=500', { cookie: adminCookie })
  assert.equal(audit.status, 200)
  const auditedPaths = new Set(audit.data.entries.map((e) => e.path))
  assert.ok(auditedPaths.has('/user-management/api/register'), 'register call audited')
  assert.ok(auditedPaths.has('/user-management/api/login'), 'login call audited')
  assert.ok(auditedPaths.has('/user-management/api/session'), 'session probe audited')
  const resetAudit = audit.data.entries.find((e) => e.path === `/user-management/api/users/${alice.id}/reset-password`)
  assert.ok(resetAudit && resetAudit.status === 200 && resetAudit.username === 'boss', 'reset-password audited with operator + status')
  const filtered = await call('/audit?path=reset-password&method=POST', { cookie: adminCookie })
  assert.ok(filtered.data.entries.every((e) => e.path.includes('reset-password') && e.method === 'POST'))

  // ── audit entries carry ids; admins can delete one entry / clear all ──
  // (the delete/clear requests are themselves audited — log hygiene leaves a
  // trace — so counts shift; assert on ids, not totals)
  assert.ok(audit.data.entries.every((e) => /^a\d+$/.test(e.id)), 'every audit entry has an id')
  assert.equal((await call(`/audit/${audit.data.entries[0].id}`, { method: 'DELETE', cookie: carolCookie })).status, 403)
  const targetId = audit.data.entries[0].id
  const delOne = await call(`/audit/${targetId}`, { method: 'DELETE', cookie: adminCookie })
  assert.equal(delOne.status, 200)
  const afterEntries = (await call('/audit', { cookie: adminCookie })).data.entries
  assert.ok(!afterEntries.some((e) => e.id === targetId), 'single entry removed')
  assert.equal((await call(`/audit/${targetId}`, { method: 'DELETE', cookie: adminCookie })).status, 404, 'deleting twice 404s')
  const idsBeforeClear = new Set(afterEntries.map((e) => e.id))
  const cleared = await call('/audit', { method: 'DELETE', cookie: adminCookie })
  assert.equal(cleared.status, 200)
  const afterClear = (await call('/audit', { cookie: adminCookie })).data.entries
  assert.ok(afterClear.every((e) => !idsBeforeClear.has(e.id)), 'ledger empty after clear (only the clear action itself may remain)')

  // ── admin user creation with role choice ──
  assert.equal((await call('/users', { method: 'POST', body: { username: 'made_admin', password: 'secret1', role: 'admin' }, cookie: carolCookie })).status, 403)
  const made = await call('/users', { method: 'POST', body: { username: 'made_admin', password: 'secret1', role: 'admin' }, cookie: adminCookie })
  assert.equal(made.status, 200)
  assert.equal(made.data.user.role, 'admin')
  const madeLogin = await call('/login', { method: 'POST', body: { username: 'made_admin', password: 'secret1' } })
  assert.equal((await call('/users', { cookie: cookieOf(madeLogin) })).data.users.length >= 2, true, 'created admin sees all users')

  // ── disable flow: kick sessions, block login, enable restores ──
  const victim = await call('/register', { method: 'POST', body: { username: 'victim', password: 'secret1' } })
  const victimCookie = cookieOf(victim)
  const victimId = victim.data.user.id
  assert.equal((await call(`/users/${victimId}/disabled`, { method: 'POST', body: { disabled: true }, cookie: victimCookie })).status, 403)
  const bossSess = await call('/session', { cookie: adminCookie })
  assert.equal((await call(`/users/${bossSess.data.user.id}/disabled`, { method: 'POST', body: { disabled: true }, cookie: adminCookie })).status, 403, 'no self-disable')
  const disable = await call(`/users/${victimId}/disabled`, { method: 'POST', body: { disabled: true }, cookie: adminCookie })
  assert.equal(disable.status, 200)
  assert.equal(disable.data.user.disabled, true)
  assert.equal((await call('/session', { cookie: victimCookie })).data.user, null, 'live session dead after disable')
  const disabledLogin = await call('/login', { method: 'POST', body: { username: 'victim', password: 'secret1' } })
  assert.equal(disabledLogin.status, 403)
  assert.ok(String(disabledLogin.data.error).includes('禁用'))
  await call(`/users/${victimId}/disabled`, { method: 'POST', body: { disabled: false }, cookie: adminCookie })
  assert.equal((await call('/login', { method: 'POST', body: { username: 'victim', password: 'secret1' } })).status, 200, 're-enabled user signs in')

  // ── IP bans: admin CRUD with self-lockout guard, gate enforces 403 ──
  assert.equal((await call('/bans', { cookie: carolCookie })).status, 403, 'plain users cannot read the ban list')
  const selfBan = await call('/bans', { method: 'POST', body: { ip: '127.0.0.1' }, cookie: adminCookie })
  assert.equal(selfBan.status, 400, 'refuses to ban the requester own IP (lockout guard)')
  const loopbackBan = await call('/bans', { method: 'POST', body: { ip: '127.0.0.55' }, cookie: adminCookie })
  assert.equal(loopbackBan.status, 400, 'loopback addresses are protected even when not the self IP')
  const badIp = await call('/bans', { method: 'POST', body: { ip: '999.9.9.9' }, cookie: adminCookie })
  assert.equal(badIp.status, 400)
  const ban = await call('/bans', { method: 'POST', body: { ip: '203.0.113.7', note: 'scanner' }, cookie: adminCookie })
  assert.equal(ban.status, 200)
  const bans = await call('/bans', { cookie: adminCookie })
  assert.ok(bans.data.bans.some((b) => b.ip === '203.0.113.7' && b.note === 'scanner'))
  assert.equal(bans.data.selfIp, '127.0.0.1')
  assert.equal((await call('/bans', { method: 'POST', body: { ip: '203.0.113.7' }, cookie: adminCookie })).status, 400, 'duplicate ban rejected')
  const unbanned = await call(`/bans/${encodeURIComponent('203.0.113.7')}`, { method: 'DELETE', cookie: adminCookie })
  assert.equal(unbanned.status, 200)
  assert.equal((await call(`/bans/${encodeURIComponent('203.0.113.7')}`, { method: 'DELETE', cookie: adminCookie })).status, 404)

  // ── logout ──
  const out = await call('/logout', { method: 'POST', cookie: carolCookie })
  assert.equal(out.status, 200)
  assert.equal((await call('/session', { cookie: carolCookie })).data.user, null)

  // ── unknown route ──
  assert.equal((await call('/nope', { cookie: adminCookie })).status, 404)
})
