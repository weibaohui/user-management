'use strict'

/**
 * dsh-plugin-user-management — Host half
 *
 * An HTTPS remote-access gateway + user administration for the dsh web
 * surface. The plugin spins up its OWN node:https listener (TLS + self-signed
 * certs + Host allow-list) that reverse-proxies to the loopback dsh
 * webserver, with user-management's own user store as the auth:
 * - Standalone /login page (login + register tabs; first registrant becomes
 *   admin). Unauthenticated page navigations redirect to /login, API/WS
 *   traffic is answered 401.
 * - Optional TOTP two-step verification (RFC 6238): self-service enrollment
 *   with QR + manual entry, OTP demanded after a correct password at login,
 *   brute-force lockout, single-use replay guard, and an admin recovery
 *   reset. See src/totp.js and the /me/totp/* + /users/:id/reset-totp APIs.
 * - JSON API under /user-management/api: sessions, self service, admin user
 *   management (list / delete / reset password / role / disable), IP bans,
 *   and the activity + audit ledgers.
 * - Everything else (the SPA, dsh /api, /plugins, static) is proxied to the
 *   loopback dsh web — but only past the auth gate, so the loopback dsh web
 *   stays unreachable directly and the auth cannot be bypassed.
 *
 * Role model: the first account registered into an empty system becomes
 * admin; later registrations are plain users. Admins manage everyone,
 * plain users see/change only themselves.
 *
 * Data lives in `$DSH_HOME/user-management/` (0600, atomic writes) — see
 * src/store.js. Self-signed certs live under `$DSH_HOME/user-management/certs/`.
 *
 * IDENTITY FOR SIBLING PLUGINS: this plugin provides the cordis service
 * `user-management` ({ resolveRequest(req), resolveToken(token) }) so any
 * host-plane plugin can map an incoming request's `um_session` cookie to
 * `{ id, username, role, ... }` — e.g. to attribute scheduled items, shares
 * or edits to a user. Consume it with RUNTIME `ctx.inject(['user-management'],
 * cb)` only (statically injecting an optional service hangs activation);
 * full examples in the README section 「给其他插件：解析请求的用户身份」 and
 * on createIdentityService below.
 *
 * The network-access layer (gateway-core/proxy/certs + hot-reload + self-heal)
 * is adapted from dsh-gateway (clarknu/dsh-gateway); the auth backend is
 * user-management's store (um_session), NOT dsh-gateway's flat HMAC users.
 */

import { readFileSync } from 'node:fs'
import fsP from 'node:fs/promises'
import { join } from 'node:path'
import { networkInterfaces, homedir } from 'node:os'
import { request as httpsRequest } from 'node:https'
import { createRequire } from 'node:module'
// 0.1.7：从宿主 dsh 全局安装的 vendored 副本同步加载 schemastery（与
// dsh-git-server / dsh-webdav-server 同源），使本插件可 link 安装而不依赖
// profile node_modules 的 bare-specifier 解析。加载失败时 z 为 null，Config
// 退化为 null（插件仍可运行，仅设置 UI 缺席）。
const __require = createRequire(import.meta.url)
function __loadSchema() {
  for (const prefix of [process.env.DSH_GLOBAL_PREFIX, homedir() + '/.local'].filter(Boolean)) {
    const target = join(prefix, 'lib', 'node_modules', '@deepseek-ai', 'dsh', 'node_modules', '@deepseek-ai', 'schemastery', 'lib', 'index.cjs')
    try { return __require(target) } catch {}
  }
  try { return __require('@deepseek-ai/schemastery') } catch {}
  return null
}
const z = __loadSchema()
import {
  createStore,
  dshHome,
  normalizeIp,
  tempPassword,
  StoreError,
  ACTIVITY_LIMIT_DEFAULT,
} from './store.js'
import { otpauthUri } from './totp.js'
import qrCodeFactory from './vendor/qrcode-generator.js'
import {
  SESSION_COOKIE,
  API_PREFIX,
  createDecider,
  parseCookies,
  isAuditableRequest,
} from './gate.js'
import { renderLoginPage } from './login-page.js'
import { createGateway } from './gateway-core.js'
import { createCertStore, inspectCertPair, CertStoreError } from './cert-store.js'

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))

const MAX_BODY_BYTES = 64 * 1024
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
/** Ledger types a plain user may read about themselves. */
const SELF_ACTIVITY_TYPES = ['login', 'login_failed', 'logout', 'password_change', 'totp_enabled', 'totp_disabled']
const ADMIN_ACTIVITY_TYPES = ['login', 'login_failed', 'logout', 'password_change', 'register', 'reset_password', 'role_change', 'delete_user', 'access', 'totp_enabled', 'totp_disabled', 'totp_reset']
const AUDIT_LIMIT_DEFAULT = 200
/** TOTP brute-force guard: lock an account's OTP check after this many
 *  consecutive bad codes (the code space is only 10^6, so without this an
 *  attacker holding the password could grind the 3-valid-codes-per-30s
 *  window indefinitely). In-memory only — a restart clears it. */
const OTP_FAIL_LIMIT = 5
const OTP_LOCKOUT_MS = 60 * 1000

/**
 * Per-username lockout after consecutive TOTP failures. Deliberately simple:
 * `fail()` counts, and reaching the limit locks for `lockoutMs` (during which
 * even a correct code is rejected — pacing attacks defeat count-only guards).
 */
function createOtpGuard({ limit = OTP_FAIL_LIMIT, lockoutMs = OTP_LOCKOUT_MS, now = () => Date.now() } = {}) {
  const state = new Map() // username(lowercased) → { fails, lockedUntil }
  const keyOf = (username) => String(username || '').toLowerCase()
  return {
    fail(username) {
      const key = keyOf(username)
      const rec = state.get(key) || { fails: 0, lockedUntil: 0 }
      rec.fails += 1
      if (rec.fails >= limit) {
        rec.lockedUntil = now() + lockoutMs
        rec.fails = 0
      }
      state.set(key, rec)
    },
    /** Remaining lockout in ms; 0 = not locked. */
    locked(username) {
      const rec = state.get(keyOf(username))
      if (!rec) return 0
      return Math.max(0, rec.lockedUntil - now())
    },
    reset(username) {
      state.delete(keyOf(username))
    },
  }
}

/** Self-contained QR SVG for the enrollment URI (white ground, scannable). */
function totpQrSvg(uri) {
  const qr = qrCodeFactory(0, 'M')
  qr.addData(uri)
  qr.make()
  return qr.createSvgTag({ cellSize: 5, margin: 2 })
}

function sendJson(res, status, payload, extraHeaders) {
  res.writeHead(status, Object.assign({ 'content-type': 'application/json; charset=utf-8' }, extraHeaders || {}))
  res.end(JSON.stringify(payload))
}

function readJsonBody(req, maxBytes = MAX_BODY_BYTES) {
  return new Promise((fulfil, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > maxBytes) { reject(new Error(`request body too large (limit ${maxBytes} bytes)`)); req.destroy(); return }
      chunks.push(chunk)
    })
    req.on('end', () => {
      try { fulfil(chunks.length === 0 ? {} : JSON.parse(Buffer.concat(chunks).toString('utf8'))) }
      catch (error) { reject(new StoreError('bad_json', `invalid JSON body: ${error && error.message}`)) }
    })
    req.on('error', reject)
  })
}

// Secure because the gateway is HTTPS-only now (the shared-server HTTP gate is gone).
function sessionCookie(token, ttlSeconds = SESSION_TTL_SECONDS) {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${ttlSeconds}`
}

function clearedCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0`
}

/** Normalize an API path: strip trailing slashes (keep the root). */
function normalizeApiPath(pathname) {
  const stripped = pathname.replace(/\/+$/, '')
  return stripped === '' ? pathname : stripped
}

function statusForStoreError(error) {
  switch (error && error.code) {
    case 'last_admin': return 409
    case 'not_found': return 404
    default: return 400
  }
}

/**
 * The full API request handler, factored out for tests. `deps`:
 * { store, clientIp(req) }.
 * Anonymous (no session) → 401 on every non-public endpoint; an authenticated
 * non-admin hitting an admin endpoint → 403. The gateway also 401s anonymous
 * non-public paths before reaching here (defense in depth), but handleApi is
 * self-consistent without it so it can be tested on a bare http server.
 */
async function handleApi(req, res, deps) {
  const url = new URL(req.url || '/', 'http://dsh.local')
  const path = normalizeApiPath(url.pathname)
  const method = (req.method || 'GET').toUpperCase()
  const { store } = deps
  const apiPath = path.startsWith(`${API_PREFIX}/`) ? path.slice(API_PREFIX.length) : path

  // Config-driven knobs (maxBodyBytes / sessionDays), read per request so a
  // settings save applies without a restart; bare harnesses (old tests) fall
  // back to the module constants.
  const readBody = () => readJsonBody(req, typeof deps.maxBodyBytes === 'function' ? deps.maxBodyBytes() : MAX_BODY_BYTES)
  const cookieFor = (token) => sessionCookie(token, typeof deps.sessionTtlSeconds === 'function' ? deps.sessionTtlSeconds() : SESSION_TTL_SECONDS)

  const authed = async () => {
    const cookies = parseCookies(req.headers && req.headers.cookie)
    return store.resolveSession(cookies[SESSION_COOKIE])
  }

  // requireAdmin: 401 anonymous, 403 authenticated non-admin, else the admin session.
  const requireAdmin = async () => {
    const session = await authed()
    if (!session) return { ok: false, status: 401, message: '未登录' }
    if (session.user.role !== 'admin') return { ok: false, status: 403, message: '需要管理员权限' }
    return { ok: true, session }
  }

  // ── anonymous endpoints ──────────────────────────────────────────────────

  if (apiPath === '/login' && method === 'POST') {
    const body = await readBody()
    const username = typeof body.username === 'string' ? body.username.trim() : ''
    const outcome = await store.checkLogin(username, body.password)
    if (outcome.result === 'invalid') {
      await store.appendActivity({ type: 'login_failed', username: username || null, ip: deps.clientIp(req), detail: 'wrong credentials' })
      return sendJson(res, 401, { error: '用户名或密码错误' })
    }
    if (outcome.result === 'disabled') {
      await store.appendActivity({ type: 'login_failed', username: username, userId: outcome.user.id, ip: deps.clientIp(req), detail: 'account disabled' })
      return sendJson(res, 403, { error: '账号已被禁用，请联系管理员' })
    }
    const user = outcome.user
    // TOTP step — only revealed AFTER the password is correct (otpRequired in
    // the response tells the login page to show the code field; a missing or
    // wrong code never discloses whether the account has TOTP to a caller who
    // doesn't hold valid credentials).
    if (user.totpSecret) {
      const guard = deps.otpGuard || (deps.otpGuard = createOtpGuard(deps.otpGuardOptions ? deps.otpGuardOptions() : {}))
      const lockedFor = guard.locked(username)
      if (lockedFor > 0) {
        await store.appendActivity({ type: 'login_failed', username, userId: user.id, ip: deps.clientIp(req), detail: 'totp attempts locked' })
        return sendJson(res, 429, { error: `两步验证失败次数过多，请 ${Math.ceil(lockedFor / 1000)} 秒后再试`, otpRequired: true })
      }
      const code = typeof body.otp === 'string' ? body.otp.trim() : ''
      if (code === '') {
        return sendJson(res, 401, { error: '请输入两步验证码', otpRequired: true })
      }
      const verdict = await store.verifyLoginOtp(user, code)
      if (!verdict.ok) {
        guard.fail(username)
        await store.appendActivity({ type: 'login_failed', username, userId: user.id, ip: deps.clientIp(req), detail: 'invalid totp' })
        return sendJson(res, 401, { error: '两步验证码错误', otpRequired: true })
      }
      guard.reset(username)
    }
    const { token } = await store.createSession(user)
    await store.touchLogin(user)
    await store.appendActivity({ type: 'login', username: user.username, userId: user.id, ip: deps.clientIp(req) })
    return sendJson(res, 200, { user: store.publicUser(user) }, { 'set-cookie': cookieFor(token) })
  }

  if (apiPath === '/register' && method === 'POST') {
    const body = await readBody()
    const username = typeof body.username === 'string' ? body.username.trim() : ''
    const role = store.roleForNextRegistration()
    // Approval mode (autoActivate off, the default): every self-registration
    // except the first admin starts DISABLED until an admin enables the
    // account — the users-table enable button is the approval action. The
    // bare-handler test harness (no deps.autoActivate) keeps classic
    // auto-activation so old flows read unchanged.
    const autoActivate = deps.autoActivate ? deps.autoActivate() === true : true
    const pending = role !== 'admin' && !autoActivate
    try {
      const created = await store.createUser({ username, password: body.password, role, disabled: pending })
      if (pending) {
        await store.appendActivity({ type: 'register', username: created.username, userId: created.id, ip: deps.clientIp(req), detail: `role=${role} pending` })
        return sendJson(res, 200, { user: created, pending: true })
      }
      const user = store.findUserByUsername(created.username)
      const { token } = await store.createSession(user)
      await store.touchLogin(user)
      await store.appendActivity({ type: 'register', username: created.username, userId: created.id, ip: deps.clientIp(req), detail: `role=${role}` })
      return sendJson(res, 200, { user: created }, { 'set-cookie': cookieFor(token) })
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, statusForStoreError(error), { error: error.message })
      throw error
    }
  }

  if (apiPath === '/session' && method === 'GET') {
    const session = await authed()
    return sendJson(res, 200, { user: session ? store.publicUser(session.user) : null })
  }

  if (apiPath === '/logout' && method === 'POST') {
    const session = await authed()
    if (session) {
      await store.dropSession(session.token)
      await store.appendActivity({ type: 'logout', username: session.user.username, userId: session.user.id, ip: deps.clientIp(req) })
    }
    return sendJson(res, 200, { ok: true }, { 'set-cookie': clearedCookie() })
  }

  // ── authenticated self service ───────────────────────────────────────────

  if (apiPath === '/me/password' && method === 'POST') {
    const session = await authed()
    if (!session) return sendJson(res, 401, { error: '未登录' })
    const body = await readBody()
    const ok = await store.verifyLogin(session.user.username, body.oldPassword)
    if (!ok) return sendJson(res, 400, { error: '当前密码不正确' })
    try {
      await store.setPassword(session.user, body.newPassword)
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, statusForStoreError(error), { error: error.message })
      throw error
    }
    await store.dropUserSessions(session.user.id, session.token)
    await store.appendActivity({ type: 'password_change', username: session.user.username, userId: session.user.id, ip: deps.clientIp(req) })
    return sendJson(res, 200, { ok: true })
  }

  // ── TOTP self-service enrollment ─────────────────────────────────────────

  // Step 1: mint the (pending) secret. The QR + otpauth URI are generated
  // here so the browser half stays bundle-light.
  if (apiPath === '/me/totp/setup' && method === 'POST') {
    const session = await authed()
    if (!session) return sendJson(res, 401, { error: '未登录' })
    try {
      const { secret } = await store.startTotpSetup(session.user)
      const uri = otpauthUri({ username: session.user.username, secret })
      return sendJson(res, 200, { secret, otpauth: uri, qrSvg: totpQrSvg(uri) })
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, 409, { error: error.message })
      throw error
    }
  }

  // Step 2: prove possession of the secret with a live code.
  if (apiPath === '/me/totp/activate' && method === 'POST') {
    const session = await authed()
    if (!session) return sendJson(res, 401, { error: '未登录' })
    const body = await readBody()
    let activated = false
    try {
      activated = await store.activateTotp(session.user, body.code)
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, 409, { error: error.message })
      throw error
    }
    if (!activated) return sendJson(res, 400, { error: '动态码不正确，请确认验证器时间已同步后重试' })
    await store.appendActivity({ type: 'totp_enabled', username: session.user.username, userId: session.user.id, ip: deps.clientIp(req) })
    return sendJson(res, 200, { ok: true })
  }

  // Disable: identity re-confirmed by password (a stolen session alone must
  // not be able to weaken the account). Existing sessions are kept — they
  // already passed the full login.
  if (apiPath === '/me/totp/disable' && method === 'POST') {
    const session = await authed()
    if (!session) return sendJson(res, 401, { error: '未登录' })
    const body = await readBody()
    const ok = await store.verifyLogin(session.user.username, body.password)
    if (!ok) return sendJson(res, 400, { error: '登录密码不正确' })
    try {
      await store.disableTotp(session.user)
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, 409, { error: error.message })
      throw error
    }
    await store.appendActivity({ type: 'totp_disabled', username: session.user.username, userId: session.user.id, ip: deps.clientIp(req) })
    return sendJson(res, 200, { ok: true })
  }

  if (apiPath === '/users' && method === 'GET') {
    const session = await authed()
    if (!session) return sendJson(res, 401, { error: '未登录' })
    if (session.user.role === 'admin') return sendJson(res, 200, { users: store.listUsers() })
    return sendJson(res, 200, { users: [store.publicUser(session.user)] })
  }

  if (apiPath === '/activity' && method === 'GET') {
    const session = await authed()
    if (!session) return sendJson(res, 401, { error: '未登录' })
    const isAdmin = session.user.role === 'admin'
    const type = url.searchParams.get('type') || undefined
    const limit = Number(url.searchParams.get('limit')) || ACTIVITY_LIMIT_DEFAULT
    if (!isAdmin) {
      const entries = await store.listActivity({ types: SELF_ACTIVITY_TYPES, userId: session.user.id, limit })
      return sendJson(res, 200, { entries })
    }
    const username = url.searchParams.get('username')
    const target = username ? store.findUserByUsername(username) : null
    const entries = await store.listActivity({
      type,
      userId: username ? (target ? target.id : 'NoSuchUser') : undefined,
      limit,
    })
    return sendJson(res, 200, { entries })
  }

  if (apiPath === '/audit' && method === 'GET') {
    const session = await authed()
    if (!session) return sendJson(res, 401, { error: '未登录' })
    if (session.user.role !== 'admin') return sendJson(res, 403, { error: '需要管理员权限' })
    const entries = await store.listAudit({
      username: url.searchParams.get('username') || undefined,
      method: url.searchParams.get('method') || undefined,
      path: url.searchParams.get('path') || undefined,
      statusClass: url.searchParams.get('statusClass') || undefined,
      limit: Number(url.searchParams.get('limit')) || AUDIT_LIMIT_DEFAULT,
    })
    return sendJson(res, 200, { entries })
  }

  if (apiPath === '/audit' && method === 'DELETE') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    await store.clearAudit()
    await store.appendActivity({ type: 'audit_clear', username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req) })
    return sendJson(res, 200, { ok: true })
  }

  if (apiPath === '/activity' && method === 'DELETE') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    await store.clearActivity()
    return sendJson(res, 200, { ok: true })
  }

  const auditDeleteMatch = /^\/audit\/([A-Za-z0-9_-]+)$/.exec(apiPath)
  if (auditDeleteMatch && method === 'DELETE') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    const removed = await store.removeAuditEntry(auditDeleteMatch[1])
    if (!removed) return sendJson(res, 404, { error: '记录不存在' })
    return sendJson(res, 200, { ok: true })
  }

  // ── admin-only IP bans ───────────────────────────────────────────────────

  if (apiPath === '/bans' && method === 'GET') {
    const session = await authed()
    if (!session) return sendJson(res, 401, { error: '未登录' })
    if (session.user.role !== 'admin') return sendJson(res, 403, { error: '需要管理员权限' })
    return sendJson(res, 200, { bans: store.listBans(), selfIp: deps.clientIp(req) })
  }

  if (apiPath === '/bans' && method === 'POST') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    const body = await readBody()
    const ip = typeof body.ip === 'string' ? body.ip.trim() : ''
    if (ip === deps.clientIp(req)) return sendJson(res, 400, { error: '不能封禁当前正在使用的 IP' })
    try {
      await store.banIp(ip, { note: body.note, by: admin.session.user.username })
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, statusForStoreError(error), { error: error.message })
      throw error
    }
    await store.appendActivity({ type: 'ban_ip', username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req), detail: `ip=${ip}${body.note ? ` note=${body.note}` : ''}` })
    return sendJson(res, 200, { ok: true })
  }

  const unbanMatch = /^\/bans\/(.+)$/.exec(apiPath)
  if (unbanMatch && method === 'DELETE') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    const ip = decodeURIComponent(unbanMatch[1])
    try {
      await store.unbanIp(ip)
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, statusForStoreError(error), { error: error.message })
      throw error
    }
    await store.appendActivity({ type: 'unban_ip', username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req), detail: `ip=${ip}` })
    return sendJson(res, 200, { ok: true })
  }

  // ── admin-only user administration ───────────────────────────────────────

  if (apiPath === '/users' && method === 'POST') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    const body = await readBody()
    try {
      const created = await store.createUser({ username: body.username, password: body.password, role: body.role || 'user' })
      await store.appendActivity({ type: 'user_created', username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req), detail: `created=${created.username} role=${created.role}` })
      return sendJson(res, 200, { user: created })
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, statusForStoreError(error), { error: error.message })
      throw error
    }
  }

  const disableMatch = /^\/users\/([A-Za-z0-9_-]+)\/disabled$/.exec(apiPath)
  if (disableMatch && method === 'POST') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    const target = store.findUser(disableMatch[1])
    if (!target) return sendJson(res, 404, { error: '用户不存在' })
    if (target.id === admin.session.user.id) return sendJson(res, 403, { error: '不能禁用自己的账号' })
    const body = await readBody()
    const disabled = !!body.disabled
    try {
      await store.setDisabled(target, disabled)
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, statusForStoreError(error), { error: error.message })
      throw error
    }
    if (disabled) await store.dropUserSessions(target.id)
    await store.appendActivity({
      type: disabled ? 'user_disabled' : 'user_enabled',
      username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req),
      detail: `target=${target.username}`,
    })
    return sendJson(res, 200, { user: store.publicUser(target) })
  }

  const adminMatch = /^\/users\/([A-Za-z0-9_-]+)(?:\/(reset-password|reset-totp|role))?$/.exec(apiPath)

  if (adminMatch && method === 'DELETE' && !adminMatch[2]) {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    const target = store.findUser(adminMatch[1])
    if (!target) return sendJson(res, 404, { error: '用户不存在' })
    if (target.id === admin.session.user.id) return sendJson(res, 403, { error: '不能删除自己的账号' })
    try {
      await store.removeUser(target)
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, statusForStoreError(error), { error: error.message })
      throw error
    }
    await store.appendActivity({ type: 'delete_user', username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req), detail: `deleted=${target.username}` })
    return sendJson(res, 200, { ok: true })
  }

  if (adminMatch && adminMatch[2] === 'reset-password' && method === 'POST') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    const target = store.findUser(adminMatch[1])
    if (!target) return sendJson(res, 404, { error: '用户不存在' })
    const generated = tempPassword()
    await store.setPassword(target, generated)
    await store.dropUserSessions(target.id)
    await store.appendActivity({ type: 'reset_password', username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req), detail: `target=${target.username}` })
    return sendJson(res, 200, { tempPassword: generated })
  }

  // Admin recovery path for a lost authenticator device: strip the target's
  // TOTP so they can sign in with the password alone (and re-enroll). Does
  // not touch their live sessions — this weakens FUTURE logins only, and the
  // action itself lands in the activity ledger.
  if (adminMatch && adminMatch[2] === 'reset-totp' && method === 'POST') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    const target = store.findUser(adminMatch[1])
    if (!target) return sendJson(res, 404, { error: '用户不存在' })
    try {
      await store.disableTotp(target)
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, 409, { error: error.message })
      throw error
    }
    await store.appendActivity({ type: 'totp_reset', username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req), detail: `target=${target.username}` })
    return sendJson(res, 200, { user: store.publicUser(target) })
  }

  if (adminMatch && adminMatch[2] === 'role' && method === 'POST') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    const target = store.findUser(adminMatch[1])
    if (!target) return sendJson(res, 404, { error: '用户不存在' })
    if (target.id === admin.session.user.id) return sendJson(res, 403, { error: '不能修改自己的角色' })
    const body = await readBody()
    try {
      await store.setRole(target, body.role)
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, statusForStoreError(error), { error: error.message })
      throw error
    }
    await store.dropUserSessions(target.id)
    await store.appendActivity({ type: 'role_change', username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req), detail: `target=${target.username} role=${target.role}` })
    return sendJson(res, 200, { user: store.publicUser(target) })
  }

  // ── admin-only gateway / HTTPS certificate management ────────────────────
  // Mechanics live in deps.gateway (createGatewayManager); this section owns
  // auth, activity-ledger entries and error mapping. Without deps.gateway
  // (bare harnesses, loopback access without the gateway) these 404 like any
  // unknown path, and the UI hides itself the same way CertCard does.

  if (apiPath === '/gateway/status' && method === 'GET') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    if (!deps.gateway) return sendJson(res, 404, { error: 'not found' })
    return sendJson(res, 200, await deps.gateway.status())
  }

  if (apiPath === '/gateway/certs' && method === 'POST') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    if (!deps.gateway) return sendJson(res, 404, { error: 'not found' })
    const body = await readBody()
    let outcome
    try {
      outcome = await deps.gateway.addCert({
        name: body.name, hosts: body.hosts, cert: body.cert, key: body.key,
        dryRun: body.dryRun === true,
        by: admin.session.user.username,
      })
    } catch (error) {
      if (error instanceof CertStoreError) return sendJson(res, 400, { error: error.message })
      throw error
    }
    if (!outcome.dryRun) {
      await store.appendActivity({
        type: 'gateway_cert_add',
        username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req),
        detail: `cert=${outcome.cert.name} hosts=${outcome.cert.hosts.join(',')}`,
      })
    }
    return sendJson(res, 200, outcome)
  }

  const gwCertMatch = /^\/gateway\/certs\/([A-Za-z0-9_-]+)$/.exec(apiPath)
  if (gwCertMatch && method === 'DELETE') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    if (!deps.gateway) return sendJson(res, 404, { error: 'not found' })
    const removed = await deps.gateway.removeCert(gwCertMatch[1])
    if (!removed) return sendJson(res, 404, { error: '证书不存在' })
    await store.appendActivity({
      type: 'gateway_cert_remove',
      username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req),
      detail: `id=${gwCertMatch[1]}`,
    })
    return sendJson(res, 200, { ok: true })
  }

  if (apiPath === '/gateway/certs/regenerate' && method === 'POST') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    if (!deps.gateway) return sendJson(res, 404, { error: 'not found' })
    const outcome = await deps.gateway.regenerateSelfSigned()
    await store.appendActivity({
      type: 'gateway_cert_regen',
      username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req),
      detail: `removed=${outcome.removed}`,
    })
    return sendJson(res, 200, outcome)
  }

  if (apiPath === '/gateway/restart' && method === 'POST') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    if (!deps.gateway) return sendJson(res, 404, { error: 'not found' })
    await store.appendActivity({
      type: 'gateway_restart',
      username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req),
    })
    void deps.gateway.restart()
    return sendJson(res, 200, { ok: true, restarting: true })
  }

  return sendJson(res, 404, { error: 'not found' })
}

// ── schemastery config (the `user-management:` settings namespace) ──────────
const Config = z && typeof z.object === 'function' ? z.object({
  enabled: z.boolean().default(true).volatile(),
  // Registration approval switch: false (default) puts every self-registered
  // account (first admin excepted) into the disabled state until an admin
  // enables it from the users table; true activates registrations immediately.
  autoActivate: z.boolean().default(false).volatile(),
  listenHost: z.string().default('0.0.0.0').volatile(),
  port: z.natural().min(1).max(65535).default(19843).volatile(),
  sites: z
    .array(
      z.object({
        hosts: z.array(z.string()).default([]),
        cert: z.string().default(''),
        key: z.string().default(''),
      }),
    )
    .default([]) // empty = auto-enumerate all local IPs (see allLocalIPs)
    .volatile(),
  title: z.string().default('DSH 控制台').volatile(),
  // sessionDays owns session lifetime (store sliding TTL + cookie Max-Age),
  // loginFailLimit/lockoutSeconds pace the TOTP brute-force guard, and
  // maxBodyBytes caps API JSON bodies (cert uploads included) — all read
  // per request/重建 so settings saves apply without a restart.
  sessionDays: z.natural().min(1).default(7).volatile(),
  loginFailLimit: z.natural().min(1).default(5).volatile(),
  lockoutSeconds: z.natural().min(1).default(60).volatile(),
  maxBodyBytes: z.natural().min(1024).default(16384).volatile(),
}) : null

/**
 * Enumerate every non-loopback local IP (IPv4 + IPv6, including Tailscale):
 * skips lo/Loopback + vEthernet/virtual/hyper-v interface names, internal
 * addresses, IPv4 APIPA (169.254.), IPv6 loopback (::1) and link-local
 * (fe80::). Accepts an optional `interfaces` arg (defaults to
 * node:os.networkInterfaces()) so the filter is unit-testable with a stub.
 */
function allLocalIPs(interfaces) {
  const ifaces = interfaces || (() => { try { return networkInterfaces() } catch { return {} } })()
  const out = []
  for (const [name, addrs] of Object.entries(ifaces)) {
    if (/^(lo|Loopback)/i.test(name)) continue
    if (/vEthernet|virtual|hyper-v/i.test(name)) continue
    for (const a of addrs || []) {
      if (a.internal) continue
      const addr = a.address || ''
      if (!addr) continue
      if (a.family === 'IPv4') {
        if (addr.startsWith('169.254.')) continue
        out.push(addr)
      } else if (a.family === 'IPv6') {
        if (addr === '::1' || addr.startsWith('fe80:')) continue
        out.push(addr)
      }
    }
  }
  return out
}

/**
 * Auto-site host list: every local IP plus its sslip.io / nip.io wildcard-DNS
 * aliases. Purely additive SAN coverage — trusting the self-signed cert once
 * then makes IP, pretty-name and wildcard-DNS access all warning-free. (It
 * does NOT remove the untrusted-cert warning by itself; for public IPs a real
 * Let's Encrypt cert via these names is the zero-warning path, and on
 * Tailscale `tailscale cert` + ts.net names remain the better choice.)
 */
function autoSiteHosts(ips) {
  const list = (ips || []).map(String)
  return ['localhost', ...list, ...list.flatMap((ip) => [`${ip}.sslip.io`, `${ip}.nip.io`])]
}

/**
 * Resolve the effective site list from config + auto-enumerated local IPs.
 *
 * MERGE semantics (v0.5.4): the auto-enumerated host list — localhost, every
 * non-loopback local IP and each IP's sslip.io / nip.io wildcard-DNS alias —
 * ALWAYS forms the self-signed certificate site, so the gateway stays
 * reachable on the LAN / Tailscale / loopback out of the box. Configured
 * sites WITHOUT cert/key are folded into that self-signed site: their hosts
 * are merged in (de-duplicated), covering names the local NICs can't see —
 * e.g. a NAT'd public IP routed to this host that no local interface owns.
 * Configured sites WITH cert/key are kept as independent SNI sites (real
 * domain certs). Empty cfg.sites is the zero-config default (pure auto).
 *
 * Before v0.5.4 a configured sites array REPLACED the auto list entirely,
 * dropping every local IP + alias and breaking local / LAN / Tailscale
 * access with 421 (unknown host) the moment a user added any site.
 */
function resolveSites(cfg, autoIps, customSites = []) {
  const configured = (cfg && cfg.sites && cfg.sites.length) ? cfg.sites : []
  const extraHosts = configured
    .filter((s) => !s.cert && !s.key)
    .flatMap((s) => s.hosts || [])
  const mergedHosts = [...new Set([...autoSiteHosts(autoIps), ...extraHosts])]
  const domainSites = configured.filter((s) => s.cert || s.key)
  // Custom sites (UI-managed cert store) come last: SNI picks the FIRST
  // matching context, so auto/settings sites keep precedence for any host
  // they also cover (the cert store refuses duplicate hosts among its own
  // entries; overlap with the auto list is intentional — local names stay
  // on the self-signed cert).
  return [{ hosts: mergedHosts, cert: '', key: '' }, ...domainSites, ...customSites]
}

/**
 * The empty-user-store guard. Previously REFUSED to start a non-loopback
 * listener with no registered users (forcing the first admin registration
 * onto loopback). Relaxed to a no-op under the zero-config default (Option B):
 * a non-loopback listener with no users STARTS and the first visitor
 * registers as admin (the user-management model). The safety message moved
 * to bootWarnings, which warns (does not refuse) in that case. Always returns
 * null (safe to apply); kept + exported for tests + forward use.
 */
function emptyUsersGuard() {
  return null
}

/**
 * Mechanics behind the /gateway/* management endpoints — certificate
 * persistence, self-signed regeneration and listener rebuilds. Factored out
 * of apply() so tests can drive the management API against a real temp dir
 * without a live listener. Endpoints (handleApi) own auth + activity
 * entries; this object owns state changes and NEVER awaits the rebuild
 * inside the request path: a sites change restarts the listener, which
 * tears down the very connection the response would travel on — the UI
 * polls /gateway/status instead.
 *
 * lifecycle: () => the status payload core (phase/port/upstream/sites…);
 *            called per status() so restarts are reflected live.
 * rebuild:   (force) => queueRebuild — fire-and-forget from here.
 */
function createGatewayManager({ certStore, certsDir, lifecycle, rebuild }) {
  /** Public (keyless) view of a stored custom cert. */
  const publicCert = (it) => ({
    id: it.id,
    name: it.name,
    hosts: it.hosts || [],
    fingerprint: it.fingerprint || '',
    notAfter: it.notAfter || '',
    subject: it.subject || '',
    expired: it.expired === true,
    createdAt: it.createdAt,
    createdBy: it.createdBy || '',
  })
  return {
    async status() {
      const base = (typeof lifecycle === 'function' ? lifecycle() : lifecycle) || {}
      let customCerts = []
      try { customCerts = (await certStore.list()).map(publicCert) } catch { /* unreadable store -> report without certs */ }
      return { ...base, sites: base.sites || [], customCerts }
    },
    /** dryRun validates + inspects without persisting (the UI's 检测 step). */
    async addCert({ name, hosts, cert, key, dryRun, by } = {}) {
      const verdict = inspectCertPair(cert, key)
      if (!verdict.ok) throw new CertStoreError('bad_pair', verdict.error)
      if (dryRun) return { ok: true, dryRun: true, info: verdict.info }
      const record = await certStore.add({ name, hosts, cert, key, by })
      void rebuild(true)
      return { ok: true, cert: record, info: verdict.info }
    },
    async removeCert(id) {
      const removed = await certStore.remove(id)
      if (removed) void rebuild(true)
      return removed
    },
    /** Delete the auto-generated pairs in the certsDir ROOT (uploads live in
     *  certs/custom/, untouched) so certs.js reissues the self-signed cert
     *  with the current host list on the next build. */
    async regenerateSelfSigned() {
      let removed = 0
      try {
        for (const name of await fsP.readdir(certsDir)) {
          if (!/\.(crt|key)$/.test(name)) continue
          try { await fsP.rm(join(certsDir, name), { force: true }); removed += 1 } catch { /* best effort */ }
        }
      } catch { /* missing dir -> nothing to remove */ }
      void rebuild(true)
      return { ok: true, removed }
    },
    async restart() {
      void rebuild(true)
      return { ok: true }
    },
  }
}

/**
 * Cordis service `user-management` — lets sibling host-plane plugins resolve
 * who is behind an incoming request. Extracted as a factory so tests can
 * exercise it without running the full apply() (which owns the gateway
 * lifecycle).
 *
 * @typedef {Object} UmUser
 * @property {string} id            stable user id (e.g. `u_3_a1b2c3d4`)
 * @property {string} username
 * @property {'admin'|'user'} role
 * @property {boolean} disabled     always false — disabled users never resolve
 * @property {number} createdAt     epoch ms
 * @property {number|null} lastLoginAt
 *
 * @example // consumer (any host-plane plugin):
 *   module.exports = {
 *     name: 'my-plugin',
 *     inject: ['webServer'],            // ← do NOT list 'user-management' here;
 *                                       //   statically injecting an optional
 *                                       //   service hangs your activation
 *     apply(ctx) {
 *       ctx.inject(['user-management'], (scope) => {
 *         const um = scope['user-management']
 *         ctx.effect(() => ctx.webServer.register({
 *           kind: 'prefix', path: '/my-plugin/api',
 *           handler: async (req, res) => {
 *             const user = await um.resolveRequest(req)
 *             if (!user) return sendJson(res, 401, { error: '未登录' })
 *             if (user.role !== 'admin') return sendJson(res, 403, { error: '需要管理员' })
 *             // user.username / user.id attribute the action
 *           },
 *         }), 'my-plugin: api')
 *       })
 *     },
 *   }
 *
 * Both resolvers await the store's async load internally, so the service is
 * safe to call as soon as it is provided. Unauthenticated / expired sessions
 * resolve to null; disabled users never resolve (the store drops their
 * sessions on disable). Browser halves of sibling plugins don't need this
 * service — they can simply `fetch('/user-management/api/session')`, which
 * the gateway answers locally with `{ user: {...} | null }`.
 *
 * @param {{ store: object, ready: Promise<object> }} opts
 * @returns {{ resolveRequest(req: object): Promise<UmUser|null>, resolveToken(token: string): Promise<UmUser|null> }}
 */
function createIdentityService({ store, ready }) {
  const withSession = async (token) => {
    try { await ready } catch { return null } // broken store → nobody resolves
    const session = await store.resolveSession(token)
    return session ? store.publicUser(session.user) : null
  }
  return {
    /** Resolve the browser request's `um_session` cookie to its user. */
    async resolveRequest(req) {
      const cookies = parseCookies(req.headers && req.headers.cookie)
      return withSession(cookies[SESSION_COOKIE])
    },
    /** Lower-level variant for callers that already extracted the token. */
    async resolveToken(token) {
      return withSession(token)
    },
  }
}

const plugin = {
  name: 'user-management',
  inject: ['webServer'],
  __internals: {
    handleApi,
    sendJson,
    readJsonBody,
    normalizeApiPath,
    statusForStoreError,
    sessionCookie,
    clearedCookie,
    SELF_ACTIVITY_TYPES,
    ADMIN_ACTIVITY_TYPES,
    AUDIT_LIMIT_DEFAULT,
    Config,
    emptyUsersGuard,
    allLocalIPs,
    autoSiteHosts,
    createIdentityService,
    resolveSites,
    createOtpGuard,
    totpQrSvg,
    createGatewayManager,
  },
  apply(ctx, config = {}) {
    const pluginName = 'user-management'

    // ── resolved config: composition config + live settings document ──────
    // 0.1.7：settings 文档里的实时 volatile 值（事件驱动刷新）。放在 apply 最前，
    // 会话 TTL / body 上限 / OTP 防爆破等 per-request 配置读它，保存即生效。
    let liveSettings = {}
    const resolvedConfig = () => ({ ...config, ...liveSettings })
    // 0.1.7：读取本命名空间在 settings 文档里的实时值（describe 投影后的 volatile
    // 字段）。settings 服务缺席时返回 {}，resolvedConfig 退回 composition config。
    const readLiveSettings = () => {
      try {
        if (!ctx.settings || typeof ctx.settings.describe !== 'function') return {}
        const d = ctx.settings.describe().find((x) => x.ns === 'user-management')
        return d && d.value ? d.value : {}
      } catch {
        return {}
      }
    }
    // sessionDays（天）→ 会话 TTL 秒；Cookie Max-Age 与 store 的 sliding TTL
    // 都读它，≤0 / 非数字回退 7 天。
    const sessionTtlSeconds = () => {
      const days = Number(resolvedConfig().sessionDays)
      return Number.isFinite(days) && days >= 1 ? Math.floor(days) * 86_400 : SESSION_TTL_SECONDS
    }
    // maxBodyBytes（API JSON 体积上限）；证书上传的 PEM 也走这里，配太小会
    // 拒绝 fullchain + 私钥（默认 16KB 足够常见证书对）。
    const maxBodyBytes = () => {
      const value = Number(resolvedConfig().maxBodyBytes)
      return Number.isFinite(value) && value >= 1024 ? Math.floor(value) : MAX_BODY_BYTES
    }
    // TOTP 防爆破：连续错 loginFailLimit 次锁 lockoutSeconds 秒。
    const otpGuardOptions = () => {
      const cfg = resolvedConfig()
      const limit = Number(cfg.loginFailLimit)
      const seconds = Number(cfg.lockoutSeconds)
      return {
        limit: Number.isFinite(limit) && limit >= 1 ? Math.floor(limit) : OTP_FAIL_LIMIT,
        lockoutMs: Number.isFinite(seconds) && seconds >= 1 ? Math.floor(seconds) * 1000 : OTP_LOCKOUT_MS,
      }
    }

    const store = createStore({ home: dshHome(), sessionTtlMs: () => sessionTtlSeconds() * 1000 })
    const ready = store.load().catch((error) => {
      console.error(`[${pluginName}] store load failed:`, error && error.message)
      throw error
    })
    const clientIp = (req) => normalizeIp(req.socket && req.socket.remoteAddress)
    const deps = { store, clientIp, sessionTtlSeconds, maxBodyBytes, otpGuardOptions }

    // Identity service for sibling plugins (see createIdentityService).
    ctx.provide('user-management', createIdentityService({ store, ready }))


    const dataDir = join(dshHome(), 'user-management')
    const certsDir = join(dataDir, 'certs')
    // UI-managed certificates (settings panel) persist under certs/custom/ —
    // the auto-generated self-signed pairs stay in the certsDir root, which
    // is what "regenerate self-signed" deletes.
    const certStore = createCertStore({ dir: join(certsDir, 'custom') })
    const certStoreReady = certStore.load().catch((error) => {
      warn(`user-management: custom cert store unavailable — UI-managed certificates disabled — ${error && error.message}`)
      return null
    })

    const log = (msg) => console.log(`[${pluginName}] ${msg}`)
    const warn = (msg) => console.warn(`[${pluginName}] ${msg}`)
    log(`gateway plugin v${pkg.version} starting (pid ${process.pid})`)

    /** The injected webServer service carries the real bound dsh port. */
    const resolveUpstream = (cfg) => {
      try {
        const ws = ctx.webServer
        if (ws && typeof ws.port === 'number') return `http://127.0.0.1:${ws.port}`
      } catch { /* fall through */ }
      warn('user-management: webServer service unavailable — assuming upstream http://127.0.0.1:3080')
      return 'http://127.0.0.1:3080'
    }

    // dsh 0.1.2-rc.1+ gates `/` index.html behind a launchToken + signed
    // browser cookie (dsh-client-connection BrowserAuth). The injected
    // `connection` service exposes the PUBLIC authenticatedUrl(baseUrl)
    // builder — the sanctioned way to obtain a token-carrying URL (reading
    // BrowserAuth.launchToken directly would couple us to a TS-private
    // field). We hand the gateway a builder that binds the token URL to the
    // upstream origin at call time, so hot-reloaded upstreams stay in sync.
    // On 0.1.1-rc.2 (no BrowserAuth) the builder stays null and the proxy
    // falls through to a plain passthrough — backward compatible.
    let authenticatedUrlBuilder = null
    if (typeof ctx.inject === 'function') {
      ctx.inject(['connection'], (fiber) => {
        try {
          // ctx.inject delivers a fiber whose `.connection` is the registered
          // HostConnectionService (cf. the existing settings inject: scope.settings).
          const conn = (fiber && fiber.connection) || fiber
          authenticatedUrlBuilder = conn && typeof conn.authenticatedUrl === 'function'
            ? (origin) => {
                try { return conn.authenticatedUrl(origin) } catch { return null }
              }
            : null
        } catch { authenticatedUrlBuilder = null }
      })
    }
    // Binds at call time: proxy.js invokes getAuthenticatedUrl(origin) and
    // needs the token URL string, not the builder function itself. Returning
    // the bare builder (v0.8.0) made new URL(fn) throw inside the mint and
    // silently skip cookie minting — masked on 0.1.1-rc.2 where the builder
    // is null and the plain-proxy fallback was used regardless.
    const getAuthenticatedUrl = (origin) => (authenticatedUrlBuilder ? authenticatedUrlBuilder(origin) : null)

    // The decider runs on every gateway request: IP-ban check (403) → session
    // resolve → gate decision (allow/redirect/401). onAccess feeds the activity
    // ledger; the gateway wires onApiRequest/onWsOpen to the audit ledger.
    const decider = createDecider({
      resolveSession: async (token) => { await ready; return store.resolveSession(token) },
      getClientIp: clientIp,
      isBanned: (ip) => store.isBanned(ip),
      onAccess: (req, resolved, path) => {
        store.appendActivity({
          type: 'access',
          username: resolved ? resolved.user.username : null,
          userId: resolved ? resolved.user.id : null,
          ip: clientIp(req),
          detail: path,
        }).catch(() => {})
      },
    })
    const auditEntry = (session, method, path, ip, status, type) => ({
      type,
      username: session ? session.user.username : null,
      userId: session ? session.user.id : null,
      ip,
      method,
      path,
      status: status === undefined ? null : status,
    })
    const auditHooks = {
      onApiRequest: (req, session, path, status) => {
        store.appendAudit(auditEntry(session, (req.method || 'GET').toUpperCase(), path, clientIp(req), status, 'api')).catch(() => {})
      },
      onWsOpen: (req, session, path) => {
        store.appendAudit(auditEntry(session, 'WS', path, clientIp(req), null, 'ws')).catch(() => {})
      },
    }

    // ── gateway lifecycle: hot-reload (bind-then-swap) + self-heal ────────
    let current = null
    let currentOptions = null
    let startedAt = null
    let lastError = ''
    let lastOnErrorAt = 0
    let restarting = false
    let rebuildChain = Promise.resolve()
    // Registration approval switch, read per request so settings hot-reload applies.
    deps.autoActivate = () => resolvedConfig().autoActivate === true
    /** Shared status projection (panel route + gateway management UI). */
    const currentPhase = (cfg) =>
      cfg.enabled === false ? 'disabled' : restarting ? 'restarting' : current ? 'running' : lastError ? 'error' : 'stopped'
    const gatewayLifecycle = () => {
      const cfg = resolvedConfig()
      return {
        version: pkg.version,
        enabled: cfg.enabled !== false,
        phase: currentPhase(cfg),
        startedAt,
        lastError,
        restarting,
        listenHost: cfg.listenHost,
        port: (current && current.port) || cfg.port,
        upstream: currentOptions ? currentOptions.upstream : resolveUpstream(cfg),
        // Per-site cert details from the LIVE listener; empty while stopped.
        sites: current ? current.describeSites() : [],
        users: store.listUsers().length,
      }
    }
    deps.gateway = createGatewayManager({ certStore, certsDir, lifecycle: gatewayLifecycle, rebuild: (force) => queueRebuild(force) })

    const queueRebuild = (force = false) => {
      rebuildChain = rebuildChain
        .then(async () => {
          await ready
          const cfg = resolvedConfig()
          // TOTP brute-force pacing follows the current settings; recreating
          // the guard resets its in-memory counters (a restart clears them
          // too — this guard was never persistent).
          deps.otpGuard = createOtpGuard(otpGuardOptions())
          if (cfg.enabled === false) {
            if (current) log('user-management: disabled — listener stopped')
            restarting = false
            stopHealthCheck()
            try { current && current.stop() } catch (e) { warn(`user-management: error stopping listener — ${e.message || e}`) }
            current = null
            currentOptions = null
            startedAt = null
            return
          }
          // Site resolution (MERGE, v0.5.4): auto-enumerated hosts (localhost
          // + every non-loopback local IP + their sslip.io / nip.io aliases)
          // always form the self-signed cert site, so the gateway stays
          // reachable on the LAN/Tailscale/loopback. Configured sites WITHOUT
          // cert/key fold their hosts into that self-signed site (covers names
          // the local NICs can't see, e.g. a NAT'd public IP); configured
          // sites WITH cert/key stay independent SNI sites (real domain
          // certs). Empty cfg.sites = pure auto (zero-config default).
          // v0.10: UI-managed custom certs (cert store, certs/custom/) are
          // appended as additional SNI sites — lowest precedence, so auto and
          // settings sites keep the hosts they cover.
          await certStoreReady
          const sites = resolveSites(cfg, allLocalIPs(), await certStore.listSites())
          const options = {
            listenHost: cfg.listenHost,
            port: cfg.port,
            upstream: resolveUpstream(cfg),
            getAuthenticatedUrl,
            sites,
            certsDir,
            title: cfg.title,
            decider,
            handleApi,
            renderLoginPage,
            deps,
            clearedCookie,
            auditHooks,
            log,
            warn,
            onError: (error) => {
              const now = Date.now()
              if (now - lastOnErrorAt < 30000) {
                warn('user-management: listener error recurring — suppressing auto-restart')
                return
              }
              lastOnErrorAt = now
              void queueRebuild(true)
            },
          }
          if (current && !force) {
            // Two-tier hot reload: request-time fields mutate in place (no gap);
            // listener-affecting fields restart the server.
            const restartNeeded =
              currentOptions.listenHost !== options.listenHost ||
              currentOptions.port !== options.port ||
              currentOptions.upstream !== options.upstream ||
              JSON.stringify(currentOptions.sites) !== JSON.stringify(options.sites)
            if (!restartNeeded) {
              restarting = false
              Object.assign(currentOptions, options)
              currentOptions.sites = options.sites
              return
            }
            log('user-management: listener settings changed — restarting')
          }
          // A listener swap tears down the very connection that requested it.
          // Give the in-flight response a beat to flush before closing the old server.
          if (current) await new Promise((resolve) => setTimeout(resolve, 120))
          restarting = true
          stopHealthCheck()
          try { current && current.stop() } catch (e) { warn(`user-management: error stopping previous listener — ${e.message || e}`) }
          current = null
          currentOptions = null
          startedAt = null
          lastError = ''
          try {
            const next = createGateway(options)
            const port = await next.start() // bind-then-swap: only publish `current` after a successful bind
            current = next
            currentOptions = options
            startedAt = new Date().toISOString()
            restarting = false
            bootWarnings(cfg, sites, port)
            startHealthCheck()
          } catch (error) {
            restarting = false
            stopHealthCheck()
            lastError = error.message || String(error)
            warn(`user-management: failed to apply configuration, gateway is down — ${lastError}`)
          }
        })
        .catch(() => {}) // a contained rebuild never poisons the chain
      return rebuildChain
    }

    function bootWarnings(cfg, sites, port) {
      const listenHost = String((cfg && cfg.listenHost) || '')
      const loopbackOnly = /^(127\.0\.0\.1|::1|localhost)$/i.test(listenHost)
      if (!loopbackOnly && store.listUsers().length === 0) {
        warn(`user-management: non-loopback listener with no registered users — the first visitor will register as admin; ensure the network is trusted (or register the first admin on loopback 127.0.0.1:${port} first)`)
      }
      const hosts = (sites || []).flatMap((s) => s.hosts || [])
      // After MERGE the self-signed site always carries localhost + every
      // local IP, so this warning only fires when there genuinely is no
      // non-loopback host anywhere (no local NICs + nothing configured) —
      // i.e. the gateway is about to be exposed with no reachable name.
      const hasNonLoopbackHost = hosts.some((h) => h && h !== 'localhost' && !/^(127\.|::1$)/.test(h))
      if (!hasNonLoopbackHost) {
        warn(`user-management: listening on port ${port} but no public hostname is configured — add sites[].hosts before exposing it`)
      }
    }

    // ── self-heal: 60s HTTPS probe, rebuild only after 3 consecutive failures ─
    let healthTimer = null
    let checking = false
    let healthFails = 0
    const HEALTH_FAIL_LIMIT = 3

    // Self-heal probe picks the first non-loopback IPv4 (falls back to loopback).
    const primaryIPv4 = () => allLocalIPs().find((ip) => ip.includes('.')) || null

    const probeHttps = (host, port, timeoutMs = 4000) =>
      new Promise((resolve) => {
        let settled = false
        const done = (ok) => { if (settled) return; settled = true; req.destroy(); resolve(ok) }
        const req = httpsRequest(
          { host, port, path: '/', method: 'GET', rejectUnauthorized: false, timeout: timeoutMs, headers: { Host: host } },
          (res) => { res.resume(); done(true) },
        )
        req.on('timeout', () => done(false))
        req.on('error', () => done(false))
        req.end()
      })

    const startHealthCheck = () => { stopHealthCheck(); healthTimer = setInterval(() => { void checkHealth() }, 60000); healthTimer.unref && healthTimer.unref() }
    const stopHealthCheck = () => { if (healthTimer) { clearInterval(healthTimer); healthTimer = null } }
    const checkHealth = async () => {
      const gw = current
      if (!gw || typeof gw.port !== 'number' || checking) return
      checking = true
      try {
        const host =
          currentOptions && currentOptions.listenHost === '0.0.0.0'
            ? (primaryIPv4() || '127.0.0.1')
            : ((currentOptions && currentOptions.listenHost) || '127.0.0.1')
        const ok = await probeHttps(host, gw.port)
        if (current !== gw) return
        if (ok) { if (healthFails > 0) healthFails = 0; return }
        healthFails += 1
        if (healthFails >= HEALTH_FAIL_LIMIT) {
          healthFails = 0
          warn(`user-management: HTTPS health check failed ${HEALTH_FAIL_LIMIT}x consecutively — listener not serving, restarting`)
          await queueRebuild(true)
        } else {
          warn(`user-management: HTTPS health check failed (${healthFails}/${HEALTH_FAIL_LIMIT}) — will retry`)
        }
      } finally {
        checking = false
      }
    }

    // ── /user-management/panel — admin-only status (reached via the gateway proxy) ─
    // Same projection the gateway's /gateway/status serves; kept for tools
    // hitting the loopback dsh web directly.
    ctx.effect(() => ctx.webServer.register({
      kind: 'prefix',
      path: '/user-management/panel',
      handler: async (req, res) => {
        const method = (req.method || 'GET').toUpperCase()
        if (method !== 'GET' && method !== 'HEAD') return sendJson(res, 405, { error: 'method not allowed' })
        await ready
        const cookies = parseCookies(req.headers && req.headers.cookie)
        const session = await store.resolveSession(cookies[SESSION_COOKIE])
        if (!session || session.user.role !== 'admin') return sendJson(res, 403, { error: '需要管理员权限' })
        return sendJson(res, 200, gatewayLifecycle())
      },
    }), `${pluginName}: panel route`)

    // ── settings namespace: 0.1.7 起通过导出 Config 自动注册；这里订阅文档
    //    更新事件刷新缓存 + 热重建（替代旧的 scope.settings.register + watch）。
    if (typeof ctx.inject === 'function') {
      ctx.inject(['settings'], () => {
        try {
          liveSettings = readLiveSettings()
          ctx.effect(() => {
            const off = ctx.on('settings/document-updated', (ns) => {
              if (ns !== 'user-management') return
              liveSettings = readLiveSettings()
              void queueRebuild()
            })
            return () => { try { off() } catch {} }
          }, 'user-management: settings watch')
          void queueRebuild()
        } catch (error) {
          warn(`user-management: settings 接线失败，仅使用 composition config — ${error.message || error}`)
          void queueRebuild()
        }
      })
    }

    // Profiles without a settings service still get the gateway from composition config.
    void queueRebuild()

    ctx.on('dispose', () => {
      stopHealthCheck()
      if (current) log('user-management: plugin disposed — stopping listener')
      try { current && current.stop() } catch (e) { warn(`user-management: error stopping listener on dispose — ${e.message || e}`) }
      current = null
    })
  },
}

export { Config }
export default plugin
