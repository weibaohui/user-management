'use strict'

/**
 * dsh-plugin-user-management — Host half
 *
 * Login gate + user administration for the dsh web server:
 * - Global auth gate over the shared node:http server (see src/gate.js):
 *   unauthenticated page navigations are redirected to `/login`, API/WS
 *   traffic is answered 401.
 * - Standalone `/login` page (login + register tabs, no host SPA needed).
 * - JSON API under `/user-management/api`: sessions, self service, admin
 *   user management (list / delete / reset password / role) and the
 *   activity ledger (login records, access records).
 *
 * Role model: the first account registered into an empty system becomes
 * admin; later registrations are plain users. Admins manage everyone,
 * plain users see/change only themselves.
 *
 * Data lives in `$DSH_HOME/user-management/` (0600, atomic writes) —
 * see src/store.js.
 */

const { join } = require('node:path')
const {
  createStore,
  dshHome,
  normalizeIp,
  tempPassword,
  StoreError,
  ACTIVITY_LIMIT_DEFAULT,
} = require('./store')
const {
  SESSION_COOKIE,
  API_PREFIX,
  createDecider,
  installGate,
  parseCookies,
} = require('./gate')
const { renderLoginPage } = require('./login-page')

const MAX_BODY_BYTES = 64 * 1024
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
/** Ledger types a plain user may read about themselves. */
const SELF_ACTIVITY_TYPES = ['login', 'login_failed', 'logout', 'password_change']
const ADMIN_ACTIVITY_TYPES = ['login', 'login_failed', 'logout', 'password_change', 'register', 'reset_password', 'role_change', 'delete_user', 'access']
const AUDIT_LIMIT_DEFAULT = 200

function sendJson(res, status, payload, extraHeaders) {
  res.writeHead(status, Object.assign({ 'content-type': 'application/json; charset=utf-8' }, extraHeaders || {}))
  res.end(JSON.stringify(payload))
}

function readJsonBody(req) {
  return new Promise((fulfil, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > MAX_BODY_BYTES) { reject(new Error('request body too large')); req.destroy(); return }
      chunks.push(chunk)
    })
    req.on('end', () => {
      try { fulfil(chunks.length === 0 ? {} : JSON.parse(Buffer.concat(chunks).toString('utf8'))) }
      catch (error) { reject(new StoreError('bad_json', `invalid JSON body: ${error && error.message}`)) }
    })
    req.on('error', reject)
  })
}

function sessionCookie(token) {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`
}

function clearedCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
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
 * The full request handler, factored out for tests. `deps`:
 * { store, resolveSession(req), clientIp(req), log(entry) }.
 */
async function handleApi(req, res, deps) {
  const url = new URL(req.url || '/', 'http://dsh.local')
  const path = normalizeApiPath(url.pathname)
  const method = (req.method || 'GET').toUpperCase()
  const { store } = deps
  const apiPath = path.startsWith(`${API_PREFIX}/`) ? path.slice(API_PREFIX.length) : path

  const authed = async () => {
    const cookies = parseCookies(req.headers && req.headers.cookie)
    return store.resolveSession(cookies[SESSION_COOKIE])
  }

  const requireAdmin = async () => {
    const session = await authed()
    if (!session || session.user.role !== 'admin') return null
    return session
  }

  // ── anonymous endpoints ──────────────────────────────────────────────────

  if (apiPath === '/login' && method === 'POST') {
    const body = await readJsonBody(req)
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
    const { token } = await store.createSession(user)
    await store.touchLogin(user)
    await store.appendActivity({ type: 'login', username: user.username, userId: user.id, ip: deps.clientIp(req) })
    return sendJson(res, 200, { user: store.publicUser(user) }, { 'set-cookie': sessionCookie(token) })
  }

  if (apiPath === '/register' && method === 'POST') {
    const body = await readJsonBody(req)
    const username = typeof body.username === 'string' ? body.username.trim() : ''
    const role = store.roleForNextRegistration()
    try {
      const created = await store.createUser({ username, password: body.password, role })
      const user = store.findUserByUsername(created.username)
      const { token } = await store.createSession(user)
      await store.touchLogin(user)
      await store.appendActivity({ type: 'register', username: created.username, userId: created.id, ip: deps.clientIp(req), detail: `role=${role}` })
      return sendJson(res, 200, { user: created }, { 'set-cookie': sessionCookie(token) })
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
    const body = await readJsonBody(req)
    const ok = await store.verifyLogin(session.user.username, body.oldPassword)
    if (!ok) return sendJson(res, 400, { error: '当前密码不正确' })
    try {
      await store.setPassword(session.user, body.newPassword)
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, statusForStoreError(error), { error: error.message })
      throw error
    }
    // keep the current session alive, kill every other one
    await store.dropUserSessions(session.user.id, session.token)
    await store.appendActivity({ type: 'password_change', username: session.user.username, userId: session.user.id, ip: deps.clientIp(req) })
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
    const session = await requireAdmin()
    if (!session) return sendJson(res, 403, { error: '需要管理员权限' })
    await store.clearAudit()
    await store.appendActivity({ type: 'audit_clear', username: session.user.username, userId: session.user.id, ip: deps.clientIp(req) })
    return sendJson(res, 200, { ok: true })
  }

  const auditDeleteMatch = /^\/audit\/([A-Za-z0-9_-]+)$/.exec(apiPath)
  if (auditDeleteMatch && method === 'DELETE') {
    const session = await requireAdmin()
    if (!session) return sendJson(res, 403, { error: '需要管理员权限' })
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
    if (!admin) return sendJson(res, 403, { error: '需要管理员权限' })
    const body = await readJsonBody(req)
    const ip = typeof body.ip === 'string' ? body.ip.trim() : ''
    // self-lockout guard: banning your own live IP would lock the whole
    // deployment (the gate runs before this API can unban it again)
    if (ip === deps.clientIp(req)) return sendJson(res, 400, { error: '不能封禁当前正在使用的 IP' })
    try {
      await store.banIp(ip, { note: body.note, by: admin.user.username })
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, statusForStoreError(error), { error: error.message })
      throw error
    }
    await store.appendActivity({ type: 'ban_ip', username: admin.user.username, userId: admin.user.id, ip: deps.clientIp(req), detail: `ip=${ip}${body.note ? ` note=${body.note}` : ''}` })
    return sendJson(res, 200, { ok: true })
  }

  const unbanMatch = /^\/bans\/(.+)$/.exec(apiPath)
  if (unbanMatch && method === 'DELETE') {
    const admin = await requireAdmin()
    if (!admin) return sendJson(res, 403, { error: '需要管理员权限' })
    const ip = decodeURIComponent(unbanMatch[1])
    try {
      await store.unbanIp(ip)
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, statusForStoreError(error), { error: error.message })
      throw error
    }
    await store.appendActivity({ type: 'unban_ip', username: admin.user.username, userId: admin.user.id, ip: deps.clientIp(req), detail: `ip=${ip}` })
    return sendJson(res, 200, { ok: true })
  }

  // ── admin-only user administration ───────────────────────────────────────

  if (apiPath === '/users' && method === 'POST') {
    const admin = await requireAdmin()
    if (!admin) return sendJson(res, 403, { error: '需要管理员权限' })
    const body = await readJsonBody(req)
    try {
      const created = await store.createUser({ username: body.username, password: body.password, role: body.role || 'user' })
      await store.appendActivity({ type: 'user_created', username: admin.user.username, userId: admin.user.id, ip: deps.clientIp(req), detail: `created=${created.username} role=${created.role}` })
      return sendJson(res, 200, { user: created })
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, statusForStoreError(error), { error: error.message })
      throw error
    }
  }

  const disableMatch = /^\/users\/([A-Za-z0-9_-]+)\/disabled$/.exec(apiPath)
  if (disableMatch && method === 'POST') {
    const admin = await requireAdmin()
    if (!admin) return sendJson(res, 403, { error: '需要管理员权限' })
    const target = store.findUser(disableMatch[1])
    if (!target) return sendJson(res, 404, { error: '用户不存在' })
    if (target.id === admin.user.id) return sendJson(res, 403, { error: '不能禁用自己的账号' })
    const body = await readJsonBody(req)
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
      username: admin.user.username, userId: admin.user.id, ip: deps.clientIp(req),
      detail: `target=${target.username}`,
    })
    return sendJson(res, 200, { user: store.publicUser(target) })
  }

  const adminMatch = /^\/users\/([A-Za-z0-9_-]+)(?:\/(reset-password|role))?$/.exec(apiPath)

  if (adminMatch && method === 'DELETE' && !adminMatch[2]) {
    const admin = await requireAdmin()
    if (!admin) return sendJson(res, 403, { error: '需要管理员权限' })
    const target = store.findUser(adminMatch[1])
    if (!target) return sendJson(res, 404, { error: '用户不存在' })
    if (target.id === admin.user.id) return sendJson(res, 403, { error: '不能删除自己的账号' })
    try {
      await store.removeUser(target)
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, statusForStoreError(error), { error: error.message })
      throw error
    }
    await store.appendActivity({ type: 'delete_user', username: admin.user.username, userId: admin.user.id, ip: deps.clientIp(req), detail: `deleted=${target.username}` })
    return sendJson(res, 200, { ok: true })
  }

  if (adminMatch && adminMatch[2] === 'reset-password' && method === 'POST') {
    const admin = await requireAdmin()
    if (!admin) return sendJson(res, 403, { error: '需要管理员权限' })
    const target = store.findUser(adminMatch[1])
    if (!target) return sendJson(res, 404, { error: '用户不存在' })
    const generated = tempPassword()
    await store.setPassword(target, generated)
    await store.dropUserSessions(target.id)
    await store.appendActivity({ type: 'reset_password', username: admin.user.username, userId: admin.user.id, ip: deps.clientIp(req), detail: `target=${target.username}` })
    return sendJson(res, 200, { tempPassword: generated })
  }

  if (adminMatch && adminMatch[2] === 'role' && method === 'POST') {
    const admin = await requireAdmin()
    if (!admin) return sendJson(res, 403, { error: '需要管理员权限' })
    const target = store.findUser(adminMatch[1])
    if (!target) return sendJson(res, 404, { error: '用户不存在' })
    if (target.id === admin.user.id) return sendJson(res, 403, { error: '不能修改自己的角色' })
    const body = await readJsonBody(req)
    try {
      await store.setRole(target, body.role)
    } catch (error) {
      if (error instanceof StoreError) return sendJson(res, statusForStoreError(error), { error: error.message })
      throw error
    }
    await store.dropUserSessions(target.id)
    await store.appendActivity({ type: 'role_change', username: admin.user.username, userId: admin.user.id, ip: deps.clientIp(req), detail: `target=${target.username} role=${target.role}` })
    return sendJson(res, 200, { user: store.publicUser(target) })
  }

  return sendJson(res, 404, { error: 'not found' })
}

module.exports = {
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
  },
  apply(ctx, config = {}) {
    const pluginName = 'user-management'
    const store = createStore({ home: dshHome() })
    const ready = store.load().catch((error) => {
      console.error(`[${pluginName}] store load failed:`, error && error.message)
      throw error
    })
    const clientIp = (req) => normalizeIp(req.socket && req.socket.remoteAddress)
    const deps = { store, clientIp }

    // GET /login — standalone login/register page
    ctx.effect(() => ctx.webServer.register({
      kind: 'exact',
      path: '/login',
      handler: async (req, res) => {
        const method = (req.method || 'GET').toUpperCase()
        if (method !== 'GET' && method !== 'HEAD') return sendJson(res, 405, { error: 'method not allowed' })
        await ready
        const html = renderLoginPage({ hasUsers: store.listUsers().length > 0, title: config.title || 'DSH 控制台' })
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
        res.end(html)
      },
    }), `${pluginName}: login page`)

    // /user-management/api/*
    ctx.effect(() => ctx.webServer.register({
      kind: 'prefix',
      path: API_PREFIX,
      handler: async (req, res) => {
        try {
          await ready
          await handleApi(req, res, deps)
        } catch (error) {
          if (!res.headersSent) sendJson(res, 500, { error: String((error && error.message) || error) })
          else res.end()
        }
      },
    }), `${pluginName}: api route`)

    // Global auth gate (hard: listener re-order; degraded: prefix '/' route)
    ctx.effect(() => {
      const auditEntry = (session, method, path, ip, status, type) => ({
        type,
        username: session ? session.user.username : null,
        userId: session ? session.user.id : null,
        ip,
        method,
        path,
        status: status === undefined ? null : status,
      })
      const decider = createDecider({
        resolveSession: async (token) => {
          await ready
          return store.resolveSession(token)
        },
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
      const hooks = {
        onApiRequest: (req, session, path, status) => {
          store.appendAudit(auditEntry(session, (req.method || 'GET').toUpperCase(), path, clientIp(req), status, 'api')).catch(() => {})
        },
        onWsOpen: (req, session, path) => {
          store.appendAudit(auditEntry(session, 'WS', path, clientIp(req), null, 'ws')).catch(() => {})
        },
      }
      const installed = installGate(ctx.webServer, decider, hooks)
      if (installed.mode === 'fallback') {
        console.warn(`[${pluginName}] webServer.server unreachable — degraded to route-level gate; /api and /plugins are NOT gated`)
      }
      return installed.dispose
    }, `${pluginName}: auth gate`)
  },
}
