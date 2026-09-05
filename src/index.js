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
 * The network-access layer (gateway-core/proxy/certs + hot-reload + self-heal)
 * is adapted from dsh-gateway (clarknu/dsh-gateway); the auth backend is
 * user-management's store (um_session), NOT dsh-gateway's flat HMAC users.
 */

const { join } = require('node:path')
const { networkInterfaces } = require('node:os')
const { request: httpsRequest } = require('node:https')
const z = require('@deepseek-ai/schemastery')
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
  parseCookies,
  isAuditableRequest,
} = require('./gate')
const { renderLoginPage } = require('./login-page')
const { createGateway } = require('./gateway-core')

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

// Secure because the gateway is HTTPS-only now (the shared-server HTTP gate is gone).
function sessionCookie(token) {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${SESSION_TTL_SECONDS}`
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
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    await store.clearAudit()
    await store.appendActivity({ type: 'audit_clear', username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req) })
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
    const body = await readJsonBody(req)
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
    const body = await readJsonBody(req)
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
      username: admin.session.user.username, userId: admin.session.user.id, ip: deps.clientIp(req),
      detail: `target=${target.username}`,
    })
    return sendJson(res, 200, { user: store.publicUser(target) })
  }

  const adminMatch = /^\/users\/([A-Za-z0-9_-]+)(?:\/(reset-password|role))?$/.exec(apiPath)

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

  if (adminMatch && adminMatch[2] === 'role' && method === 'POST') {
    const admin = await requireAdmin()
    if (!admin.ok) return sendJson(res, admin.status, { error: admin.message })
    const target = store.findUser(adminMatch[1])
    if (!target) return sendJson(res, 404, { error: '用户不存在' })
    if (target.id === admin.session.user.id) return sendJson(res, 403, { error: '不能修改自己的角色' })
    const body = await readJsonBody(req)
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

  return sendJson(res, 404, { error: 'not found' })
}

// ── schemastery config (the `user-management:` settings namespace) ──────────
const Config = z.object({
  enabled: z.boolean().default(true),
  listenHost: z.string().default('127.0.0.1'),
  port: z.natural().min(1).max(65535).default(19843),
  sites: z
    .array(
      z.object({
        hosts: z.array(z.string()).default([]),
        cert: z.string().default(''),
        key: z.string().default(''),
      }),
    )
    .default([{ hosts: ['localhost'], cert: '', key: '' }]),
  title: z.string().default('DSH 控制台'),
  // Reserved (accepted, not wired): the store owns session lifetime, login
  // failure is not auto-locked (admins set IP bans instead), and handleApi
  // owns its own body-size cap. Kept for the settings card + forward use.
  sessionDays: z.natural().min(1).default(7),
  loginFailLimit: z.natural().min(1).default(5),
  lockoutSeconds: z.natural().min(1).default(60),
  maxBodyBytes: z.natural().min(1024).default(16384),
})

/**
 * Fail-closed gate, analogous to dsh-gateway's admin/change-me guard but for
 * an empty user store: a non-loopback listener with NO registered users would
 * let the first caller register as admin over the network. Refuse to start
 * (keep any running listener up) until the first admin is registered on
 * loopback. Returns an error message or null when safe to apply.
 */
function emptyUsersGuard(cfg, store) {
  const listenHost = String(cfg && cfg.listenHost || '')
  const loopbackOnly = /^(127\.0\.0\.1|::1|localhost)$/i.test(listenHost)
  if (!loopbackOnly && store.listUsers().length === 0) {
    return 'refusing to apply: non-loopback listener with no registered users — register the first admin on loopback first (open the gateway URL from the host)'
  }
  return null
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

    const dataDir = join(dshHome(), 'user-management')
    const certsDir = join(dataDir, 'certs')

    const log = (msg) => console.log(`[${pluginName}] ${msg}`)
    const warn = (msg) => console.warn(`[${pluginName}] ${msg}`)
    log(`gateway plugin v${require('../package.json').version} starting (pid ${process.pid})`)

    /** The injected webServer service carries the real bound dsh port. */
    const resolveUpstream = (cfg) => {
      try {
        const ws = ctx.webServer
        if (ws && typeof ws.port === 'number') return `http://127.0.0.1:${ws.port}`
      } catch { /* fall through */ }
      warn('user-management: webServer service unavailable — assuming upstream http://127.0.0.1:3080')
      return 'http://127.0.0.1:3080'
    }

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
    let settingsScope = null
    let current = null
    let currentOptions = null
    let startedAt = null
    let lastError = ''
    let lastOnErrorAt = 0
    let restarting = false
    let rebuildChain = Promise.resolve()
    const resolvedConfig = () => (settingsScope ? settingsScope.get() : config)

    const queueRebuild = (force = false) => {
      rebuildChain = rebuildChain
        .then(async () => {
          await ready
          const cfg = resolvedConfig()
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
          // Fail-closed: refuse a non-loopback listener with no users.
          const guardError = emptyUsersGuard(cfg, store)
          if (guardError) {
            restarting = false
            if (current && !force) {
              warn(`user-management: ${guardError} — kept the running listener; register the first admin or restrict to loopback`)
            } else {
              stopHealthCheck()
              try { current && current.stop() } catch (e) { warn(`user-management: error stopping listener — ${e.message || e}`) }
              current = null
              currentOptions = null
              startedAt = null
              lastError = guardError
              warn(`user-management: ${guardError}`)
            }
            return
          }
          const options = {
            listenHost: cfg.listenHost,
            port: cfg.port,
            upstream: resolveUpstream(cfg),
            sites: cfg.sites || [{ hosts: ['localhost'] }],
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
            bootWarnings(cfg, port)
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

    function bootWarnings(cfg, port) {
      if (store.listUsers().length === 0) {
        warn(`user-management: no users registered — open the gateway URL to register the first admin`)
      }
      const hosts = (cfg.sites || []).flatMap((s) => s.hosts || [])
      if (hosts.length === 0 || (hosts.length === 1 && hosts[0] === 'localhost')) {
        warn(`user-management: listening on port ${port} but no public hostname is configured — add sites[].hosts before exposing it`)
      }
    }

    // ── self-heal: 60s HTTPS probe, rebuild only after 3 consecutive failures ─
    let healthTimer = null
    let checking = false
    let healthFails = 0
    const HEALTH_FAIL_LIMIT = 3

    const primaryIPv4 = () => {
      try {
        for (const [name, addrs] of Object.entries(networkInterfaces())) {
          if (/^(lo|Loopback)/i.test(name)) continue
          if (/vEthernet|virtual|hyper-v/i.test(name)) continue
          for (const a of addrs || []) {
            if (a.family !== 'IPv4' || a.internal) continue
            if (a.address.startsWith('169.254.')) continue
            return a.address
          }
        }
      } catch { /* fall through to loopback */ }
      return null
    }

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
        const cfg = resolvedConfig()
        const phase = cfg.enabled === false ? 'disabled' : restarting ? 'restarting' : current ? 'running' : lastError ? 'error' : 'stopped'
        return sendJson(res, 200, {
          version: require('../package.json').version,
          enabled: cfg.enabled !== false,
          phase,
          startedAt,
          lastError,
          listenHost: cfg.listenHost,
          port: (current && current.port) || cfg.port,
          sites: (cfg.sites || []).map((s) => ({ hosts: s.hosts || [], cert: s.cert ? 'file' : 'auto' })),
          users: store.listUsers().length,
        })
      },
    }), `${pluginName}: panel route`)

    // ── settings namespace: hot-reload on every committed change ────────────
    if (typeof ctx.inject === 'function') {
      ctx.inject(['settings'], (scope) => {
        try {
          const registration = scope.settings.register('user-management', Config, { base: config })
          settingsScope = registration
          registration.watch(() => { void queueRebuild() })
          void queueRebuild()
        } catch (error) {
          warn(`user-management: settings namespace unavailable, using the composition config only — ${error.message || error}`)
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

module.exports = plugin
