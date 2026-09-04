'use strict'

/**
 * Global auth gate for the shared dsh node:http server.
 *
 * The host router (exact / longest-prefix / fallback) does not compose
 * middleware, and the `/api` + `/plugins` prefixes are already taken — so a
 * route-level gate can never cover them. The gate therefore re-orders
 * listeners on the public `webServer.server` instance: capture the existing
 * `request`/`upgrade` listeners, remove them, and install a gate that either
 * responds itself (unauthenticated) or replays the captured listeners
 * (authenticated / public path). This is a deliberate, documented hack; see
 * README "安全模型". A degraded route-level gateway (prefix `/` + passthrough
 * to the captured fallback handler) is provided for hosts where the server
 * instance is not reachable — it cannot cover `/api` + `/plugins`.
 *
 * The decision core is a pure function so tests can cover it without a
 * server; attachGate / installFallbackGate are thin machinery around it.
 */

const LOGIN_PAGE_PATH = '/login'
const API_PREFIX = '/user-management/api'
/** Paths reachable without a session (login page + auth API itself). */
const PUBLIC_PATHS = [
  LOGIN_PAGE_PATH,
  `${API_PREFIX}/login`,
  `${API_PREFIX}/register`,
  `${API_PREFIX}/session`,
  `${API_PREFIX}/logout`,
]

function isPublicPath(path) {
  return PUBLIC_PATHS.some((entry) => path === entry || path.startsWith(`${entry}/`) || path.startsWith(`${entry}?`))
}

/** Document request = a browser navigation (GET/HEAD asking for text/html). */
function isDocumentRequest(method, acceptHeader) {
  if (method !== 'GET' && method !== 'HEAD') return false
  const accept = String(acceptHeader || '')
  return accept.includes('text/html')
}

const STATIC_SUFFIX_RE = /\.(?:js|mjs|css|map|woff2?|ttf|otf|png|jpe?g|gif|svg|ico|webp|avif|mp4|webmanifest|txt)$/i

/** Static asset (bundle files, fonts, images) — never audit-logged. */
function isStaticAsset(path) {
  return STATIC_SUFFIX_RE.test(String(path || ''))
}

/** API-ish request worth auditing: neither a page navigation nor an asset. */
function isAuditableRequest(method, acceptHeader, path) {
  return !isDocumentRequest(method, acceptHeader) && !isStaticAsset(path)
}

function parseCookies(header) {
  const out = {}
  const raw = String(header || '')
  if (raw === '') return out
  for (const pair of raw.split(';')) {
    const eq = pair.indexOf('=')
    if (eq === -1) continue
    const key = pair.slice(0, eq).trim()
    if (key === '') continue
    out[key] = decodeURIComponent(pair.slice(eq + 1).trim())
  }
  return out
}

/**
 * Pure gate decision.
 * @param {object} input
 * @param {string} input.method
 * @param {string} input.path          pathname only (no query)
 * @param {string} input.accept        raw Accept header
 * @param {boolean} input.sessionValid whether the session cookie resolves
 * @returns {{action:'allow'} | {action:'redirect', location:string} | {action:'unauthorized'}}
 */
function gateDecision({ method, path, accept, sessionValid }) {
  if (sessionValid) return { action: 'allow' }
  if (isPublicPath(path)) return { action: 'allow' }
  if (isDocumentRequest(method, accept)) return { action: 'redirect', location: LOGIN_PAGE_PATH }
  return { action: 'unauthorized' }
}

/**
 * Decide from a live request. `resolveSession(req)` → truthy when the
 * request carries a valid session. Two audit hooks:
 * - `onAccess(req, session, path)` fires for document navigations that pass
 *   the gate (the "access ledger");
 * - allow decisions carry `{ session, path }` so attachGate can record the
 *   operation audit (API/WebSocket) once the response completes.
 */
function createDecider({ resolveSession, onAccess }) {
  return async function decide(req) {
    let url
    try {
      url = new URL(req.url || '/', 'http://dsh.local')
    } catch {
      return { action: 'unauthorized' }
    }
    const method = (req.method || 'GET').toUpperCase()
    const cookies = parseCookies(req.headers && req.headers.cookie)
    const resolved = await resolveSession(cookies[SESSION_COOKIE])
    const decision = gateDecision({
      method,
      path: url.pathname,
      accept: req.headers && req.headers.accept,
      sessionValid: !!resolved,
    })
    if (decision.action === 'allow') {
      decision.session = resolved
      decision.path = url.pathname
      if (onAccess && isDocumentRequest(method, req.headers && req.headers.accept) && !isPublicPath(url.pathname)) {
        try { onAccess(req, resolved, url.pathname) } catch { /* ledger must never break the gate */ }
      }
    }
    return decision
  }
}

const SESSION_COOKIE = 'um_session'

function sendUnauthorized(res) {
  res.writeHead(401, { 'content-type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify({ error: 'unauthorized' }))
}

function denySocket(socket) {
  try {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
  } catch { /* socket may already be gone */ }
  socket.destroy()
}

/**
 * Install the gate over a live node:http Server by re-ordering listeners.
 * `hooks.onApiRequest(req, session, path, status)` fires once the response
 * of an auditable (non-document, non-asset) request completes;
 * `hooks.onWsOpen(req, session, path)` fires when a WebSocket upgrade
 * passes the gate. Returns a disposer restoring the original wiring.
 */
function attachGate(server, decider, hooks = {}) {
  const requestListeners = server.listeners('request').slice()
  server.removeAllListeners('request')
  const requestGate = (req, res) => {
    Promise.resolve()
      .then(() => decider(req))
      .then((decision) => {
        if (decision.action === 'allow') {
          if (typeof hooks.onApiRequest === 'function' && isAuditableRequest((req.method || 'GET').toUpperCase(), req.headers && req.headers.accept, decision.path)) {
            res.on('finish', () => {
              try { hooks.onApiRequest(req, decision.session, decision.path, res.statusCode) } catch { /* audit must never break the gate */ }
            })
          }
          for (const listener of requestListeners) listener.call(server, req, res)
          return
        }
        if (decision.action === 'redirect') {
          res.writeHead(302, { location: decision.location || LOGIN_PAGE_PATH })
          res.end()
          return
        }
        sendUnauthorized(res)
      })
      .catch(() => {
        if (!res.headersSent) sendUnauthorized(res)
        else res.end()
      })
  }
  server.addListener('request', requestGate)

  const upgradeListeners = server.listeners('upgrade').slice()
  let upgradeGate = null
  if (upgradeListeners.length > 0) {
    server.removeAllListeners('upgrade')
    upgradeGate = (req, socket, head) => {
      Promise.resolve()
        .then(() => decider(req))
        .then((decision) => {
          if (decision.action === 'allow') {
            if (typeof hooks.onWsOpen === 'function') {
              try { hooks.onWsOpen(req, decision.session, decision.path) } catch { /* audit must never break the gate */ }
            }
            for (const listener of upgradeListeners) listener.call(server, req, socket, head)
            return
          }
          denySocket(socket)
        })
        .catch(() => denySocket(socket))
    }
    server.addListener('upgrade', upgradeGate)
  }

  return function dispose() {
    server.removeListener('request', requestGate)
    server.removeAllListeners('request')
    for (const listener of requestListeners) server.addListener('request', listener)
    if (upgradeGate !== null) {
      server.removeListener('upgrade', upgradeGate)
      server.removeAllListeners('upgrade')
      for (const listener of upgradeListeners) server.addListener('upgrade', listener)
    }
  }
}

/**
 * Degraded gate for hosts where the server instance is unreachable: a
 * prefix-`/` route wrapping the (captured) fallback handler. Known blind
 * spots — `/api` and `/plugins` prefixes outrank `/` and are NOT covered
 * (documented in README). Audit hooks behave like the hard gate.
 */
function installFallbackGate(webServer, decider, hooks = {}) {
  const inner = typeof webServer.fallback === 'function' ? webServer.fallback : null
  webServer.register({
    kind: 'prefix',
    path: '/',
    handler: async (req, res) => {
      let decision
      try { decision = await decider(req) } catch { decision = { action: 'unauthorized' } }
      if (decision.action === 'allow') {
        if (typeof hooks.onApiRequest === 'function' && isAuditableRequest((req.method || 'GET').toUpperCase(), req.headers && req.headers.accept, decision.path)) {
          res.on('finish', () => {
            try { hooks.onApiRequest(req, decision.session, decision.path, res.statusCode) } catch { /* audit must never break the gate */ }
          })
        }
        if (inner) return inner(req, res)
        res.writeHead(404)
        res.end()
        return
      }
      if (decision.action === 'redirect') {
        res.writeHead(302, { location: decision.location || LOGIN_PAGE_PATH })
        res.end()
        return
      }
      sendUnauthorized(res)
    },
  })
  return () => {}
}

/**
 * Try the hard gate first; fall back to the route-level gateway when the
 * server instance is not reachable (host upgrades may change internals).
 * Returns { mode, dispose }.
 */
function installGate(webServer, decider, hooks = {}) {
  const server = webServer && webServer.server
  if (server && typeof server.listeners === 'function' && typeof server.addListener === 'function') {
    try {
      const dispose = attachGate(server, decider, hooks)
      return { mode: 'server', dispose }
    } catch { /* fall through to degraded mode */ }
  }
  return { mode: 'fallback', dispose: installFallbackGate(webServer, decider, hooks) }
}

module.exports = {
  SESSION_COOKIE,
  LOGIN_PAGE_PATH,
  API_PREFIX,
  PUBLIC_PATHS,
  gateDecision,
  createDecider,
  attachGate,
  installFallbackGate,
  installGate,
  parseCookies,
  isDocumentRequest,
  isStaticAsset,
  isAuditableRequest,
  isPublicPath,
  sendUnauthorized,
}
