'use strict'

/**
 * user-management store — users / sessions / activity ledger.
 *
 * Everything lives under `$DSH_HOME/user-management/`:
 * - users.json     accounts (scrypt password hashes), mode 0600, atomic writes
 * - sessions.json  issued session tokens (survive restarts), same protection
 * - activity.jsonl append-only event ledger (logins, admin actions, page
 *                  accesses), rolled over to the tail MAX_LEDGER_LINES
 *
 * No third-party dependencies: hashing is crypto.scrypt, tokens are
 * crypto.randomBytes. All mutation paths are async and serialize through
 * per-file write chains so concurrent requests cannot interleave writes.
 */

const fsP = require('node:fs/promises')
const net = require('node:net')
const { randomBytes, scrypt: scryptCb, timingSafeEqual, createHash } = require('node:crypto')
const { promisify } = require('node:util')
const { join } = require('node:path')

const scrypt = promisify(scryptCb)

const USERS_FILE = 'users.json'
const SESSIONS_FILE = 'sessions.json'
const ACTIVITY_FILE = 'activity.jsonl'
const AUDIT_FILE = 'audit.jsonl'
const BANS_FILE = 'bans.json'

/** scrypt key length / cost — modest defaults, login is not a hot path. */
const KEY_LEN = 32
const SCRYPT_COST = 16384
/** Session lifetime; sliding — each authenticated check past half-life renews. */
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000
const SESSION_RENEW_MS = SESSION_TTL_MS / 2
/** Ledger rollover: trim to the tail once the file grows past 2× the cap. */
const MAX_LEDGER_LINES = 2000
/** Operation audit ledger (separate file — must not be rolled away by
 *  security events or vice versa). Same 2× trim rule. */
const MAX_AUDIT_LINES = 5000

const USERNAME_RE = /^[a-zA-Z0-9_-]{2,32}$/
const MIN_PASSWORD_LEN = 6
const ACTIVITY_LIMIT_DEFAULT = 200

class StoreError extends Error {
  constructor(code, message) {
    super(message)
    this.code = code
  }
}

/** dsh data root — mirrors the host ($DSH_HOME, default ~/.dsh). */
function dshHome() {
  return process.env.DSH_HOME ? require('node:path').resolve(process.env.DSH_HOME) : join(require('node:os').homedir(), '.dsh')
}

function isValidUsername(name) {
  return typeof name === 'string' && USERNAME_RE.test(name)
}

function isValidPassword(pw) {
  return typeof pw === 'string' && pw.length >= MIN_PASSWORD_LEN && pw.length <= 256
}

async function hashPassword(password, salt) {
  const useSalt = salt || randomBytes(16).toString('hex')
  const derived = await scrypt(password, useSalt, KEY_LEN, { N: SCRYPT_COST, r: 8, p: 1 })
  return { salt: useSalt, passHash: derived.toString('hex') }
}

/** Constant-time password check against a stored {salt, passHash} record. */
function verifyPassword(record, password) {
  if (!record || !record.salt || !record.passHash || typeof password !== 'string') return false
  const { scryptSync } = require('node:crypto')
  const derived = scryptSync(password, record.salt, KEY_LEN, { N: SCRYPT_COST, r: 8, p: 1 })
  const expected = Buffer.from(record.passHash, 'hex')
  if (derived.length !== expected.length) return false
  return timingSafeEqual(derived, expected)
}

/** Random URL-safe token (session ids, one-time reset passwords). */
function randomToken(bytes = 32) {
  return randomBytes(bytes).toString('base64url')
}

/** Temps are 12 chars but human-typeable: groups of 4. */
function tempPassword() {
  const raw = randomToken(9) // 12 base64url chars
  return raw.slice(0, 4) + '-' + raw.slice(4, 8) + '-' + raw.slice(8, 12)
}

/** Stable token fingerprint for ledger entries — never log the token itself. */
function tokenFingerprint(token) {
  return createHash('sha256').update(String(token)).digest('hex').slice(0, 12)
}

function normalizeIp(raw) {
  if (!raw) return ''
  let ip = String(raw)
  if (ip.startsWith('::ffff:')) ip = ip.slice(7)
  if (ip === '::1') ip = '127.0.0.1'
  return ip
}

/**
 * Create a store rooted at `<home>/user-management`. All state is cached in
 * memory after load; writes persist through serialized atomic replacements.
 */
function createStore({ home, now = () => Date.now() } = {}) {
  const dir = join(home, 'user-management')
  const usersFile = join(dir, USERS_FILE)
  const sessionsFile = join(dir, SESSIONS_FILE)
  const activityFile = join(dir, ACTIVITY_FILE)
  const auditFile = join(dir, AUDIT_FILE)
  const bansFile = join(dir, BANS_FILE)

  /** @type {{seq:number, users:Array}} */
  let usersDoc = { seq: 0, users: [] }
  /** @type {{tokens:Object<string,{userId,username,createdAt,expiresAt}>}} */
  let sessionsDoc = { tokens: {} }
  /** @type {{bans:Array<{ip,note,createdAt,createdBy}>}} */
  let bansDoc = { bans: [] }
  let ledgerLines = 0
  let auditLines = 0
  let auditSeq = 0
  const writeChain = { users: Promise.resolve(), sessions: Promise.resolve(), ledger: Promise.resolve(), audit: Promise.resolve() }

  function atomicWrite(file, content) {
    return fsP.mkdir(dir, { recursive: true }).then(() => {
      const temp = join(dir, `.${randomBytes(6).toString('hex')}.tmp`)
      return fsP.writeFile(temp, content, { encoding: 'utf8', mode: 0o600 })
        .then(() => fsP.rename(temp, file))
    })
  }

  function persistUsers() {
    const run = writeChain.users.then(() => atomicWrite(usersFile, JSON.stringify(usersDoc, null, 2)))
    writeChain.users = run.catch(() => {})
    return run
  }

  function persistBans() {
    const run = writeChain.users.then(() => atomicWrite(bansFile, JSON.stringify(bansDoc, null, 2)))
    writeChain.users = run.catch(() => {})
    return run
  }

  function persistSessions() {
    const run = writeChain.sessions.then(() => atomicWrite(sessionsFile, JSON.stringify(sessionsDoc)))
    writeChain.sessions = run.catch(() => {})
    return run
  }

  async function load() {
    await fsP.mkdir(dir, { recursive: true })
    for (const [file, assign] of [
      [usersFile, (data) => { usersDoc = data }],
      [sessionsFile, (data) => { sessionsDoc = data }],
      [bansFile, (data) => { bansDoc = data }],
    ]) {
      try {
        const raw = await fsP.readFile(file, 'utf8')
        const parsed = JSON.parse(raw)
        if (parsed && typeof parsed === 'object') assign(parsed)
      } catch (e) {
        if (e && e.code !== 'ENOENT') throw e
      }
    }
    if (!Array.isArray(usersDoc.users)) usersDoc.users = []
    if (!Number.isFinite(usersDoc.seq)) usersDoc.seq = usersDoc.users.length
    if (!sessionsDoc.tokens || typeof sessionsDoc.tokens !== 'object') sessionsDoc.tokens = {}
    if (!Array.isArray(bansDoc.bans)) bansDoc.bans = []
    // expired tokens are dropped on boot; ledger line count for rollover
    const ts = now()
    for (const token of Object.keys(sessionsDoc.tokens)) {
      if (!sessionsDoc.tokens[token] || sessionsDoc.tokens[token].expiresAt <= ts) delete sessionsDoc.tokens[token]
    }
    try { ledgerLines = (await fsP.readFile(activityFile, 'utf8')).split('\n').filter((l) => l.trim() !== '').length } catch { ledgerLines = 0 }
    try {
      const raw = await fsP.readFile(auditFile, 'utf8')
      const lines = raw.split('\n').filter((l) => l.trim() !== '')
      auditLines = lines.length
      for (const line of lines) {
        try {
          const id = JSON.parse(line).id
          const match = typeof id === 'string' ? /^a(\d+)$/.exec(id) : null
          if (match) auditSeq = Math.max(auditSeq, Number(match[1]))
        } catch { /* skip malformed line */ }
      }
    } catch { auditLines = 0 }
    return { users: usersDoc.users.length, sessions: Object.keys(sessionsDoc.tokens).length }
  }

  // ── users ────────────────────────────────────────────────────────────────

  function publicUser(user) {
    if (!user) return null
    return {
      id: user.id, username: user.username, role: user.role,
      disabled: !!user.disabled,
      createdAt: user.createdAt, lastLoginAt: user.lastLoginAt || null,
    }
  }

  function findUser(id) {
    return usersDoc.users.find((u) => u.id === id) || null
  }

  function findUserByUsername(username) {
    const needle = String(username || '').toLowerCase()
    return usersDoc.users.find((u) => u.username.toLowerCase() === needle) || null
  }

  function countAdmins() {
    return usersDoc.users.filter((u) => u.role === 'admin').length
  }

  async function createUser({ username, password, role = 'user' }) {
    if (!isValidUsername(username)) throw new StoreError('bad_username', '用户名需 2-32 位，仅限字母/数字/下划线/连字符')
    if (!isValidPassword(password)) throw new StoreError('bad_password', `密码至少 ${MIN_PASSWORD_LEN} 位`)
    if (findUserByUsername(username)) throw new StoreError('duplicate', '用户名已存在')
    if (role !== 'admin' && role !== 'user') throw new StoreError('bad_role', 'role 必须是 admin 或 user')
    const { salt, passHash } = await hashPassword(password)
    const user = {
      id: `u_${++usersDoc.seq}_${randomToken(6)}`,
      username: String(username),
      role,
      salt,
      passHash,
      createdAt: now(),
      lastLoginAt: null,
    }
    usersDoc.users.push(user)
    await persistUsers()
    return publicUser(user)
  }

  /** First account in an empty system becomes admin (see README). */
  function roleForNextRegistration() {
    return usersDoc.users.length === 0 ? 'admin' : 'user'
  }

  async function verifyLogin(username, password) {
    const outcome = await checkLogin(username, password)
    return outcome.result === 'ok' || outcome.result === 'disabled' ? outcome.user : null
  }

  /**
   * Full login outcome: 'ok' | 'invalid' | 'disabled' (correct credentials
   * but the account is disabled). The invalid path burns hash time so
   * missing users are not distinguishable; the disabled path only exists
   * behind correct credentials, so revealing it is safe.
   */
  async function checkLogin(username, password) {
    const user = findUserByUsername(username)
    if (!user) {
      await hashPassword(password || '', '00000000000000000000000000000000')
      return { result: 'invalid' }
    }
    if (!verifyPassword(user, password)) return { result: 'invalid' }
    return { result: user.disabled ? 'disabled' : 'ok', user }
  }

  /** Disable / enable an account. Disabled users fail login and lose all
   *  live sessions (resolveSession also re-checks the flag defensively). */
  async function setDisabled(user, disabled) {
    if (typeof disabled !== 'boolean') throw new StoreError('bad_request', 'disabled 必须是布尔值')
    if (disabled && user.role === 'admin' && countAdmins() <= 1) {
      throw new StoreError('last_admin', '不能禁用最后一个管理员')
    }
    if (disabled) user.disabled = true
    else delete user.disabled
    await persistUsers()
  }

  async function setPassword(user, password) {
    if (!isValidPassword(password)) throw new StoreError('bad_password', `密码至少 ${MIN_PASSWORD_LEN} 位`)
    const { salt, passHash } = await hashPassword(password)
    user.salt = salt
    user.passHash = passHash
    await persistUsers()
  }

  async function setRole(user, role) {
    if (role !== 'admin' && role !== 'user') throw new StoreError('bad_role', 'role 必须是 admin 或 user')
    if (user.role === 'admin' && role !== 'admin' && countAdmins() <= 1) {
      throw new StoreError('last_admin', '不能降级最后一个管理员')
    }
    user.role = role
    await persistUsers()
  }

  async function removeUser(user) {
    const index = usersDoc.users.indexOf(user)
    if (index === -1) throw new StoreError('not_found', '用户不存在')
    if (user.role === 'admin' && countAdmins() <= 1) {
      throw new StoreError('last_admin', '不能删除最后一个管理员')
    }
    usersDoc.users.splice(index, 1)
    for (const token of Object.keys(sessionsDoc.tokens)) {
      if (sessionsDoc.tokens[token].userId === user.id) delete sessionsDoc.tokens[token]
    }
    await persistUsers()
    return persistSessions()
  }

  async function touchLogin(user) {
    user.lastLoginAt = now()
    await persistUsers()
  }

  function listUsers() {
    return usersDoc.users.map(publicUser)
  }

  // ── sessions ─────────────────────────────────────────────────────────────

  async function createSession(user) {
    const token = randomToken()
    const ts = now()
    sessionsDoc.tokens[token] = { userId: user.id, username: user.username, createdAt: ts, expiresAt: ts + SESSION_TTL_MS }
    await pruneSessions()
    return { token, expiresAt: ts + SESSION_TTL_MS }
  }

  async function pruneSessions() {
    const ts = now()
    for (const token of Object.keys(sessionsDoc.tokens)) {
      const session = sessionsDoc.tokens[token]
      if (!session || session.expiresAt <= ts) delete sessionsDoc.tokens[token]
    }
    return persistSessions()
  }

  /** Resolve a token → {user, session, token}. Sliding renewal past half-life. */
  async function resolveSession(token) {
    if (!token || typeof token !== 'string') return null
    const session = sessionsDoc.tokens[token]
    if (!session) return null
    const ts = now()
    if (session.expiresAt <= ts) {
      delete sessionsDoc.tokens[token]
      await persistSessions()
      return null
    }
    const user = findUser(session.userId)
    if (!user) {
      delete sessionsDoc.tokens[token]
      await persistSessions()
      return null
    }
    if (user.disabled) {
      delete sessionsDoc.tokens[token]
      await persistSessions()
      return null
    }
    if (session.expiresAt - ts < SESSION_RENEW_MS) {
      session.expiresAt = ts + SESSION_TTL_MS
      await persistSessions()
    }
    return { user, session, token }
  }

  async function dropSession(token) {
    if (token && sessionsDoc.tokens[token]) {
      delete sessionsDoc.tokens[token]
      await persistSessions()
    }
  }

  /** Kill every session of a user (password reset / role change / delete). */
  async function dropUserSessions(userId, exceptToken) {
    let dropped = false
    for (const token of Object.keys(sessionsDoc.tokens)) {
      if (sessionsDoc.tokens[token].userId !== userId) continue
      if (token === exceptToken) continue
      delete sessionsDoc.tokens[token]
      dropped = true
    }
    if (dropped) await persistSessions()
  }

  // ── IP bans ──────────────────────────────────────────────────────────────

  function isBanned(ip) {
    if (!ip) return false
    return bansDoc.bans.some((b) => b.ip === ip)
  }

  function listBans() {
    return bansDoc.bans.slice().sort((a, b) => b.createdAt - a.createdAt)
  }

  /** Ban an IP (validated). The self-lockout guard lives in the API layer —
   *  it needs the requester's live IP, the store does not. */
  async function banIp(ip, { note = '', by = null } = {}) {
    const normalized = String(ip || '').trim()
    if (net.isIP(normalized) === 0) throw new StoreError('bad_ip', '不是合法的 IP 地址')
    if (isBanned(normalized)) throw new StoreError('duplicate', '该 IP 已在封禁列表')
    bansDoc.bans.push({ ip: normalized, note: String(note || '').slice(0, 140), createdAt: now(), createdBy: by })
    return persistBans()
  }

  async function unbanIp(ip) {
    const before = bansDoc.bans.length
    bansDoc.bans = bansDoc.bans.filter((b) => b.ip !== ip)
    if (bansDoc.bans.length === before) throw new StoreError('not_found', '该 IP 不在封禁列表')
    return persistBans()
  }

  // ── activity + audit ledgers ─────────────────────────────────────────────

  function ledgerLine(entry) {
    return JSON.stringify({
      ts: now(),
      type: entry.type,
      username: entry.username || null,
      userId: entry.userId || null,
      ip: entry.ip || '',
      detail: entry.detail || '',
    })
  }

  /** Serialized append to a JSONL ledger with 2×-cap tail rollover. */
  function appendJsonl({ file, line, getLines, setLines, cap }) {
    const run = writeChain.ledger
      .then(() => fsP.appendFile(file, line + '\n', { encoding: 'utf8', mode: 0o600 }))
      .then(async () => {
        setLines(getLines() + 1)
        if (getLines() > cap * 2) {
          const raw = await fsP.readFile(file, 'utf8')
          const lines = raw.split('\n').filter((l) => l.trim() !== '')
          const keep = lines.slice(-cap)
          setLines(keep.length)
          await atomicWrite(file, keep.join('\n') + '\n')
        }
      })
    writeChain.ledger = run.catch(() => {})
    return run
  }

  async function appendActivity(entry) {
    return appendJsonl({
      file: activityFile,
      line: ledgerLine(entry),
      getLines: () => ledgerLines,
      setLines: (n) => { ledgerLines = n },
      cap: MAX_LEDGER_LINES,
    })
  }

  /** Operation audit: every gated API/WebSocket action of a signed-in user. */
  async function appendAudit(entry) {
    const id = `a${++auditSeq}`
    return appendJsonl({
      file: auditFile,
      line: JSON.stringify({
        id,
        ts: now(),
        type: entry.type || 'api',
        username: entry.username || null,
        userId: entry.userId || null,
        ip: entry.ip || '',
        method: entry.method || '',
        path: entry.path || '',
        status: entry.status || null,
      }),
      getLines: () => auditLines,
      setLines: (n) => { auditLines = n },
      cap: MAX_AUDIT_LINES,
    })
  }

  /** Remove one audit entry by id (admin manual cleanup). */
  async function removeAuditEntry(id) {
    const run = writeChain.ledger.then(async () => {
      let raw = ''
      try { raw = await fsP.readFile(auditFile, 'utf8') } catch { return false }
      const lines = raw.split('\n').filter((l) => l.trim() !== '')
      const kept = []
      let removed = false
      for (const line of lines) {
        try {
          if (JSON.parse(line).id === id) { removed = true; continue }
        } catch { /* keep malformed lines as-is */ }
        kept.push(line)
      }
      if (!removed) return false
      auditLines = kept.length
      await atomicWrite(auditFile, kept.length === 0 ? '' : kept.join('\n') + '\n')
      return true
    })
    writeChain.ledger = run.catch(() => {})
    return run
  }

  /** Drop the entire audit ledger (admin manual cleanup). */
  async function clearAudit() {
    const run = writeChain.ledger.then(async () => {
      auditLines = 0
      await atomicWrite(auditFile, '')
    })
    writeChain.ledger = run.catch(() => {})
    return run
  }

  /**
   * Read ledger entries newest-first. Filters: type (exact), userId, and a
   * set of types (`types`). `limit` caps the scan window from the tail.
   */
  async function listActivity({ type, types, userId, limit = ACTIVITY_LIMIT_DEFAULT } = {}) {
    return listJsonl(activityFile, (entry) => {
      if (type && entry.type !== type) return false
      if (types) {
        const set = Array.isArray(types) ? new Set(types) : types
        if (!set.has(entry.type)) return false
      }
      if (userId && entry.userId !== userId) return false
      return true
    }, limit)
  }

  /**
   * Read the operation audit newest-first. Filters: username, method
   * (exact), path substring, and a response-status class ('2'|'3'|'4'|'5').
   */
  async function listAudit({ username, method, path, statusClass, limit = ACTIVITY_LIMIT_DEFAULT } = {}) {
    return listJsonl(auditFile, (entry) => {
      if (username && entry.username !== username) return false
      if (method && entry.method !== method) return false
      if (path && !String(entry.path || '').includes(path)) return false
      if (statusClass && String(entry.status || '').charAt(0) !== statusClass) return false
      return true
    }, limit)
  }

  async function listJsonl(file, predicate, limit) {
    let raw = ''
    try { raw = await fsP.readFile(file, 'utf8') } catch { return [] }
    const lines = raw.split('\n').filter((l) => l.trim() !== '')
    const cap = Math.max(1, Math.min(Number(limit) || ACTIVITY_LIMIT_DEFAULT, MAX_AUDIT_LINES))
    const out = []
    for (let i = lines.length - 1; i >= 0 && out.length < cap; i -= 1) {
      let entry
      try { entry = JSON.parse(lines[i]) } catch { continue }
      if (predicate(entry)) out.push(entry)
    }
    return out
  }

  return {
    // lifecycle
    load,
    // users
    createUser, verifyLogin, checkLogin, setPassword, setRole, setDisabled, removeUser, touchLogin,
    listUsers, findUser, findUserByUsername, countAdmins, roleForNextRegistration, publicUser,
    // sessions
    createSession, resolveSession, dropSession, dropUserSessions, pruneSessions,
    // ip bans
    isBanned, listBans, banIp, unbanIp,
    // ledger
    appendActivity, listActivity, appendAudit, listAudit, removeAuditEntry, clearAudit,
    // internals for tests
    __files: { dir, usersFile, sessionsFile, activityFile, auditFile, bansFile },
    __state: () => ({ users: usersDoc.users, sessions: sessionsDoc.tokens, ledgerLines, auditLines, bans: bansDoc.bans }),
    StoreError,
  }
}

module.exports = {
  createStore,
  dshHome,
  isValidUsername,
  isValidPassword,
  verifyPassword,
  hashPassword,
  randomToken,
  tempPassword,
  tokenFingerprint,
  normalizeIp,
  StoreError,
  SESSION_TTL_MS,
  SESSION_RENEW_MS,
  MAX_LEDGER_LINES,
  MAX_AUDIT_LINES,
  USERNAME_RE,
  MIN_PASSWORD_LEN,
  ACTIVITY_LIMIT_DEFAULT,
}
