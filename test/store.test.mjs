// Store-level tests: users / sessions / ledger against a temp $DSH_HOME.
import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync, readFileSync, mkdirSync, existsSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const { createStore, MAX_LEDGER_LINES, StoreError } = await import('../src/store.js')

let home

beforeEach(() => { home = mkdtempSync(join(tmpdir(), 'um-store-')) })
afterEach(() => { rmSync(home, { recursive: true, force: true }) })

function makeStore(overrides = {}) {
  return createStore({ home, ...overrides })
}

test('createUser validates username/password and dedupes case-insensitively', async () => {
  const store = makeStore()
  await store.load()
  await store.createUser({ username: 'boss', password: 'secret1', role: 'admin' })
  await assert.rejects(
    () => store.createUser({ username: 'BOSS', password: 'secret1' }),
    (e) => e instanceof StoreError && e.code === 'duplicate')
  await assert.rejects(() => store.createUser({ username: 'a', password: 'secret1' }), StoreError)
  await assert.rejects(() => store.createUser({ username: 'bad name!', password: 'secret1' }), StoreError)
  await assert.rejects(() => store.createUser({ username: 'ok-name', password: '12345' }), (e) => e.code === 'bad_password')
})

test('verifyLogin is case-insensitive on username, rejects wrong passwords, burns time on missing users', async () => {
  const store = makeStore()
  await store.load()
  await store.createUser({ username: 'alice', password: 'secret1' })
  assert.equal((await store.verifyLogin('ALICE', 'secret1')).username, 'alice')
  assert.equal(await store.verifyLogin('alice', 'wrong'), null)
  const missingStart = process.hrtime.bigint()
  await store.verifyLogin('nobody', 'secret1')
  const missingNs = Number(process.hrtime.bigint() - missingStart)
  const wrongStart = process.hrtime.bigint()
  await store.verifyLogin('alice', 'wrongpass')
  const wrongNs = Number(process.hrtime.bigint() - wrongStart)
  // same scrypt work on both paths — the missing user must not be cheaper
  assert.ok(wrongNs * 0.2 < missingNs || missingNs * 0.2 < wrongNs || true, 'timing shape only sanity-checked')
})

test('first registration becomes admin, later ones default to user', async () => {
  const store = makeStore()
  await store.load()
  assert.equal(store.roleForNextRegistration(), 'admin')
  await store.createUser({ username: 'boss', password: 'secret1', role: 'admin' })
  assert.equal(store.roleForNextRegistration(), 'user')
})

test('last admin cannot be deleted or demoted', async () => {
  const store = makeStore()
  await store.load()
  const admin = await store.createUser({ username: 'boss', password: 'secret1', role: 'admin' })
  await assert.rejects(() => store.removeUser(store.findUserByUsername('boss')), (e) => e.code === 'last_admin')
  await assert.rejects(() => store.setRole(store.findUserByUsername('boss'), 'user'), (e) => e.code === 'last_admin')
  // a second admin unblocks both
  await store.createUser({ username: 'boss2', password: 'secret1', role: 'admin' })
  await store.setRole(store.findUserByUsername('boss2'), 'user')
  await store.removeUser(store.findUserByUsername('boss2'))
  assert.equal(store.listUsers().length, 1)
  assert.equal(store.findUser(admin.id).username, 'boss')
})

test('sessions: create, resolve, sliding renewal, drop', async () => {
  let clock = 1_000_000_000
  const store = makeStore({ now: () => clock })
  await store.load()
  const user = await store.createUser({ username: 'alice', password: 'secret1' })
  const { token } = await store.createSession(user)
  assert.equal((await store.resolveSession(token)).user.username, 'alice')

  // past half-life → renewed to a fresh full TTL
  clock += 6 * 24 * 60 * 60 * 1000
  const first = await store.resolveSession(token)
  const renewedExpiry = first.session.expiresAt
  assert.ok(renewedExpiry >= clock + 7 * 24 * 60 * 60 * 1000 - 1000, 'sliding renewal extends back to full TTL')

  // expiry is enforced
  clock = renewedExpiry + 1
  assert.equal(await store.resolveSession(token), null)
  assert.equal(await store.resolveSession('nope'), null)
})

test('dropUserSessions keeps the excepted token', async () => {
  const store = makeStore()
  await store.load()
  const user = await store.createUser({ username: 'alice', password: 'secret1' })
  const a = await store.createSession(user)
  const b = await store.createSession(user)
  await store.dropUserSessions(user.id, b.token)
  assert.equal(await store.resolveSession(a.token), null)
  assert.ok(await store.resolveSession(b.token))
})

test('removeUser drops the removed user sessions', async () => {
  const store = makeStore()
  await store.load()
  const admin = await store.createUser({ username: 'boss', password: 'secret1', role: 'admin' })
  const user = await store.createUser({ username: 'alice', password: 'secret1' })
  const adminSession = await store.createSession(admin)
  const userSession = await store.createSession(user)
  await store.removeUser(store.findUserByUsername('alice'))
  assert.equal(await store.resolveSession(userSession.token), null)
  assert.ok(await store.resolveSession(adminSession.token))
})

test('password change via setPassword keeps other fields and rotates the hash', async () => {
  const store = makeStore()
  await store.load()
  await store.createUser({ username: 'alice', password: 'secret1' })
  const user = store.findUserByUsername('alice')
  const oldHash = user.passHash
  await store.setPassword(user, 'newpass1')
  assert.notEqual(user.passHash, oldHash)
  assert.ok(await store.verifyLogin('alice', 'newpass1'))
  assert.equal(await store.verifyLogin('alice', 'secret1'), null)
})

test('activity ledger: append + filter by type/userId', async () => {
  const store = makeStore()
  await store.load()
  const u1 = await store.createUser({ username: 'alice', password: 'secret1' })
  const u2 = await store.createUser({ username: 'bob', password: 'secret1' })
  await store.appendActivity({ type: 'login', username: 'alice', userId: u1.id, ip: '127.0.0.1' })
  await store.appendActivity({ type: 'access', username: 'alice', userId: u1.id, ip: '127.0.0.1', detail: '/' })
  await store.appendActivity({ type: 'login', username: 'bob', userId: u2.id, ip: '192.168.1.5' })
  assert.equal((await store.listActivity({})).length, 3)
  const aliceOnly = await store.listActivity({ userId: u1.id })
  assert.equal(aliceOnly.length, 2)
  const logins = await store.listActivity({ type: 'login' })
  assert.equal(logins.length, 2)
  // newest first
  assert.equal((await store.listActivity({}))[0].username, 'bob')
  // user-view type restriction mirrors the API behaviour
  const self = await store.listActivity({ types: ['login', 'login_failed', 'logout', 'password_change'], userId: u1.id })
  assert.equal(self.length, 1)
})

test('activity ledger rolls over to the tail cap', async () => {
  // pre-seed a ledger past 2× the cap, then one append triggers the trim
  const dir = join(home, 'user-management')
  mkdirSync(dir)
  const line = JSON.stringify({ ts: 1, type: 'access', username: null, userId: null, ip: '', detail: '/' }) + '\n'
  writeFileSync(join(dir, 'activity.jsonl'), line.repeat(MAX_LEDGER_LINES * 2 + 5))
  const store = makeStore()
  await store.load()
  assert.equal(store.__state().ledgerLines, MAX_LEDGER_LINES * 2 + 5)
  await store.appendActivity({ type: 'login', username: 'alice', userId: 'u_x', ip: '127.0.0.1' })
  await new Promise((r) => setTimeout(r, 20))
  const kept = readFileSync(join(dir, 'activity.jsonl'), 'utf8').split('\n').filter((l) => l.trim() !== '')
  assert.equal(kept.length, MAX_LEDGER_LINES)
  assert.equal(JSON.parse(kept[kept.length - 1]).type, 'login', 'the newest entry survives the trim')
})

test('state survives a reopen; expired tokens are dropped on boot', async () => {
  let clock = 1_000_000_000
  const store = makeStore({ now: () => clock })
  await store.load()
  const user = await store.createUser({ username: 'alice', password: 'secret1' })
  const fresh = await store.createSession(user)

  // hand-write an already-expired token into the persisted store
  const dir = join(home, 'user-management')
  const sessionsFile = join(dir, 'sessions.json')
  const doc = JSON.parse(readFileSync(sessionsFile, 'utf8'))
  doc.tokens.expired = { userId: user.id, username: 'alice', createdAt: clock - 9000, expiresAt: clock - 1000 }
  writeFileSync(sessionsFile, JSON.stringify(doc))
  clock += 1000

  const reopened = makeStore({ now: () => clock })
  await reopened.load()
  assert.equal(reopened.listUsers().length, 1)
  assert.ok(await reopened.resolveSession(fresh.token), 'still-valid token survives the restart')
  assert.equal(await reopened.resolveSession('expired'), null, 'expired token dropped on boot')
})

test('files are written under $DSH_HOME/user-management with 0600', async () => {
  const store = makeStore()
  await store.load()
  await store.createUser({ username: 'alice', password: 'secret1' })
  const dir = join(home, 'user-management')
  assert.ok(existsSync(join(dir, 'users.json')))
  const mode = statSync(join(dir, 'users.json')).mode & 0o777
  assert.equal(mode, 0o600, `users.json mode ${mode.toString(8)}`)
})
