'use strict'

/**
 * Pure auth-gate decision core for the user-management gateway.
 *
 * The gateway listener (src/gateway-core.js) calls `createDecider(...)` on
 * every request: it checks IP bans first (403, login page included), resolves
 * the um_session cookie against the store, and returns the gate decision
 * (allow / redirect-to-login / unauthorized / forbidden). The gateway then
 * routes accordingly (local API/login page vs. reverse-proxy) and wires the
 * audit hooks on response completion.
 *
 * Previously this module also installed a gate by re-ordering listeners on the
 * shared dsh node:http server (attachGate / installFallbackGate / installGate).
 * That shared-server gate is gone — the gateway listener IS the gate now, so
 * the auth cannot be bypassed by hitting the loopback dsh web directly. Only
 * the pure, testable decision core remains here.
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
 * request carries a valid session. `isBanned(ip)` runs BEFORE any session
 * work: a banned source IP is denied everything (403), login page included.
 * Two audit hooks:
 * - `onAccess(req, session, path)` fires for document navigations that pass
 *   the gate (the "access ledger");
 * - allow decisions carry `{ session, path }` so the gateway can record the
 *   operation audit (API/WebSocket) once the response completes.
 */
function createDecider({ resolveSession, onAccess, getClientIp, isBanned }) {
  return async function decide(req) {
    let url
    try {
      url = new URL(req.url || '/', 'http://dsh.local')
    } catch {
      return { action: 'unauthorized' }
    }
    const method = (req.method || 'GET').toUpperCase()
    const ip = getClientIp ? getClientIp(req) : ''
    if (isBanned && ip && isBanned(ip)) return { action: 'forbidden', path: url.pathname }
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

function sendForbidden(res, message) {
  res.writeHead(403, { 'content-type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify({ error: message || 'forbidden' }))
}

module.exports = {
  SESSION_COOKIE,
  LOGIN_PAGE_PATH,
  API_PREFIX,
  PUBLIC_PATHS,
  gateDecision,
  createDecider,
  parseCookies,
  isDocumentRequest,
  isStaticAsset,
  isAuditableRequest,
  isPublicPath,
  sendUnauthorized,
  sendForbidden,
}
