/**
 * dsh-plugin-user-management - Browser half.
 *
 * One React surface: the settings-page section (family convention — the
 * only management entry). Admins get the full user table plus the login /
 * access ledgers; plain users get their own profile card, password change
 * and their own login records. All colors come from the ui-theme
 * `--dsw-*` token layers so light/dark follows the shell; all copy comes
 * from the locale registry (`zh`/`en`). No hardcoded colors, no ad-hoc copy.
 */

// React is a loader platform module. Under plain Node (contract tests) a
// minimal createElement/hook shim keeps the source loadable for assertions.
let __React = null
try { __React = require('react') } catch {}
if (!__React || typeof __React.createElement !== 'function') {
  __React = {
    createElement(type, props, ...kids) {
      return { type, props: props || {}, kids: kids.flat(9).filter((k) => k !== null && k !== undefined && k !== false && k !== true) }
    },
    useState(init) { const v = [typeof init === 'function' ? init() : init]; return [v[0], (x) => { v[0] = typeof x === 'function' ? x(v[0]) : x }] },
    useEffect() {}, useMemo(fn) { return fn() }, useRef(v = null) { return { current: v } },
  }
}
const { createElement: h, useState, useEffect, useMemo, useRef } = __React

// react-dom is a loader platform module (portals + createRoot). Under plain
// Node (contract tests) it is absent; every use site guards on it and
// degrades (menu renders inline-less null, settings section skips mount).
let RDP = null
try { RDP = require('react-dom') } catch {}

const CLIENT_NAME = '@weibaohui/user-management'
const NS = 'user-management'

// ── locale ────────────────────────────────────────────────────────────────

const ZH = {
  title: '用户管理',
  loading: '加载中…',
  notLoggedIn: '当前浏览器未登录（会话可能已过期），刷新页面重新登录。',
  reload: '刷新',
  tabUsers: '用户',
  tabLoginLog: '登录记录',
  tabAccessLog: '访问记录',
  colUser: '用户名',
  colRole: '角色',
  colCreatedAt: '创建时间',
  colLastLogin: '最后登录',
  colTime: '时间',
  colType: '类型',
  colIp: 'IP',
  colDetail: '详情',
  colMethod: '方法',
  colPath: '路径',
  colStatus: '状态',
  tabAuditLog: '操作日志',
  filterPath: '按路径过滤…',
  statusAll: '全部状态',
  statusOk: '成功 (2xx)',
  statusErr: '失败 (4xx/5xx)',
  typeWsConn: 'WS 连接',
  roleAdmin: '管理员',
  roleUser: '普通用户',
  you: '（我）',
  actionResetPwd: '重置密码',
  actionSetAdmin: '设为管理员',
  actionSetUser: '降为普通用户',
  actionDelete: '删除',
  resetPwdConfirm: '重置 {name} 的密码？该用户的所有登录会话将被强制登出。',
  deleteConfirm: '删除用户 {name}？此操作不可恢复。',
  roleConfirm: '将 {name} 的角色变更为 {role}？该用户将被强制重新登录。',
  tempPwdTitle: '临时密码',
  tempPwdHint: '已为 {name} 重置密码，请立即保存，仅显示这一次：',
  copy: '复制',
  copied: '已复制',
  filterUser: '按用户名过滤…',
  filterAll: '全部类型',
  myInfo: '我的信息',
  changePwd: '修改密码',
  oldPwd: '当前密码',
  newPwd: '新密码（至少 6 位）',
  confirmPwd: '确认新密码',
  save: '保存',
  pwdChanged: '密码已修改，其他会话已登出',
  pwdMismatch: '两次输入的新密码不一致',
  empty: '暂无记录',
  opOk: '操作成功',
  failed: '操作失败：',
  clearLog: '清空',
  clearLogConfirm: '确定清空全部操作日志？此操作不可恢复。',
  delEntryConfirm: '删除这条操作记录？',
  auditCleared: '操作日志已清空',
  entryDeleted: '记录已删除',
  actionLogout: '退出登录',
  createUser: '新增用户',
  createUserTitle: '新增用户',
  colPassword: '密码（至少 6 位）',
  colRolePick: '角色',
  submitCreate: '创建',
  userCreated: '用户已创建',
  actionDisable: '禁用',
  actionEnable: '启用',
  badgeDisabled: '已禁用',
  disableConfirm: '禁用 {name}？该用户的登录会话将被立即踢出，且无法再登录。',
  enableConfirm: '启用 {name}？该用户将可以重新登录。',
  tabBans: 'IP 封禁',
  banIpPlaceholder: '输入 IP 地址…',
  banNotePlaceholder: '备注（可选）',
  banAction: '封禁',
  unbanAction: '解封',
  colNote: '备注',
  colBannedBy: '封禁者',
  banConfirm: '封禁 {ip}？该地址将无法访问任何页面与接口。',
  unbanConfirm: '解封 {ip}？',
  banned: 'IP 已封禁',
  unbanned: 'IP 已解封',
  selfIp: '（当前）',
  bannedShort: '已封',
  typeUserCreated: '创建用户',
  typeUserDisabled: '禁用用户',
  typeUserEnabled: '启用用户',
  typeBanIp: '封禁 IP',
  typeUnbanIp: '解封 IP',
  typeLogin: '登录',
  typeLoginFailed: '登录失败',
  typeLogout: '登出',
  typePasswordChange: '修改密码',
  typeRegister: '注册',
  typeResetPassword: '重置密码',
  typeRoleChange: '角色变更',
  typeDeleteUser: '删除用户',
  typeAccess: '页面访问',
  userCount: '{n} 个用户',
}

const EN = {
  title: 'User Management',
  loading: 'Loading…',
  notLoggedIn: 'Not signed in (session may have expired) — refresh the page to sign in again.',
  reload: 'Refresh',
  tabUsers: 'Users',
  tabLoginLog: 'Login Records',
  tabAccessLog: 'Access Records',
  colUser: 'Username',
  colRole: 'Role',
  colCreatedAt: 'Created',
  colLastLogin: 'Last Login',
  colTime: 'Time',
  colType: 'Type',
  colIp: 'IP',
  colDetail: 'Detail',
  colMethod: 'Method',
  colPath: 'Path',
  colStatus: 'Status',
  tabAuditLog: 'Operation Log',
  filterPath: 'Filter by path…',
  statusAll: 'All statuses',
  statusOk: 'Success (2xx)',
  statusErr: 'Failed (4xx/5xx)',
  typeWsConn: 'WS connection',
  roleAdmin: 'Admin',
  roleUser: 'User',
  you: ' (me)',
  actionResetPwd: 'Reset Password',
  actionSetAdmin: 'Make Admin',
  actionSetUser: 'Demote to User',
  actionDelete: 'Delete',
  resetPwdConfirm: "Reset {name}'s password? All their sessions will be signed out.",
  deleteConfirm: 'Delete user {name}? This cannot be undone.',
  roleConfirm: "Change {name}'s role to {role}? They will be signed out.",
  tempPwdTitle: 'Temporary Password',
  tempPwdHint: "Password reset for {name}. Save it now — shown only once:",
  copy: 'Copy',
  copied: 'Copied',
  filterUser: 'Filter by username…',
  filterAll: 'All types',
  myInfo: 'My Profile',
  changePwd: 'Change Password',
  oldPwd: 'Current password',
  newPwd: 'New password (min 6 chars)',
  confirmPwd: 'Confirm new password',
  save: 'Save',
  pwdChanged: 'Password changed; other sessions signed out',
  pwdMismatch: 'The two new passwords do not match',
  empty: 'No records',
  opOk: 'Done',
  failed: 'Operation failed: ',
  clearLog: 'Clear',
  clearLogConfirm: 'Clear the entire operation log? This cannot be undone.',
  delEntryConfirm: 'Delete this audit entry?',
  auditCleared: 'Operation log cleared',
  entryDeleted: 'Entry deleted',
  actionLogout: 'Sign out',
  createUser: 'New User',
  createUserTitle: 'New User',
  colPassword: 'Password (min 6 chars)',
  colRolePick: 'Role',
  submitCreate: 'Create',
  userCreated: 'User created',
  actionDisable: 'Disable',
  actionEnable: 'Enable',
  badgeDisabled: 'Disabled',
  disableConfirm: 'Disable {name}? Their sessions are signed out immediately and they can no longer sign in.',
  enableConfirm: 'Enable {name}? They will be able to sign in again.',
  tabBans: 'IP Bans',
  banIpPlaceholder: 'Enter an IP address…',
  banNotePlaceholder: 'Note (optional)',
  banAction: 'Ban',
  unbanAction: 'Unban',
  colNote: 'Note',
  colBannedBy: 'Banned by',
  banConfirm: 'Ban {ip}? This address will be unable to reach any page or API.',
  unbanConfirm: 'Unban {ip}?',
  banned: 'IP banned',
  unbanned: 'IP unbanned',
  selfIp: ' (current)',
  bannedShort: 'Banned',
  typeUserCreated: 'User created',
  typeUserDisabled: 'User disabled',
  typeUserEnabled: 'User enabled',
  typeBanIp: 'IP banned',
  typeUnbanIp: 'IP unbanned',
  typeLogin: 'Login',
  typeLoginFailed: 'Login failed',
  typeLogout: 'Logout',
  typePasswordChange: 'Password change',
  typeRegister: 'Register',
  typeResetPassword: 'Password reset',
  typeRoleChange: 'Role change',
  typeDeleteUser: 'User deleted',
  typeAccess: 'Page access',
  userCount: '{n} user(s)',
}

/** Ledger event type → locale key (also the login-log type filter). */
const TYPE_LABELS = {
  login: 'typeLogin',
  login_failed: 'typeLoginFailed',
  logout: 'typeLogout',
  password_change: 'typePasswordChange',
  register: 'typeRegister',
  reset_password: 'typeResetPassword',
  role_change: 'typeRoleChange',
  delete_user: 'typeDeleteUser',
  access: 'typeAccess',
  user_created: 'typeUserCreated',
  user_disabled: 'typeUserDisabled',
  user_enabled: 'typeUserEnabled',
  ban_ip: 'typeBanIp',
  unban_ip: 'typeUnbanIp',
}

// ── helpers ───────────────────────────────────────────────────────────────

function api(path, options = {}) {
  const init = { method: options.method || 'GET', headers: {} }
  if (options.body !== undefined) {
    init.headers['content-type'] = 'application/json'
    init.body = JSON.stringify(options.body)
  }
  return fetch('/user-management/api' + path, init).then(async (res) => {
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`)
    return data
  })
}

function formatTime(ts) {
  if (!ts) return '-'
  try { return new Date(ts).toLocaleString() } catch { return '-' }
}

function interpolate(template, vars) {
  let out = template
  for (const [key, value] of Object.entries(vars || {})) out = out.split('{' + key + '}').join(String(value))
  return out
}

/** Client-side tab filters for the admin login-records ledger. */
function filterActivity(entries, { username, type } = {}) {
  return (entries || []).filter((entry) => {
    if (username && entry.username !== username) return false
    if (type && entry.type !== type) return false
    return true
  })
}

/** Client-side filters for the operation audit ledger. */
function filterAudit(entries, { username, method, path, statusClass } = {}) {
  return (entries || []).filter((entry) => {
    if (username && entry.username !== username) return false
    if (method && entry.method !== method) return false
    if (path && !String(entry.path || '').includes(path)) return false
    if (statusClass && String(entry.status || '').charAt(0) !== statusClass) return false
    return true
  })
}

/** Loopback / self addresses must never be bannable (defense in depth —
 *  the server refuses them too). */
const LOOPBACK_IP_RE = /^127(?:\.\d{1,3}){3}$|^::1$|^\[::1\]$/

function canBanIp(ip, selfIp) {
  if (!ip || ip === '-') return false
  if (LOOPBACK_IP_RE.test(ip)) return false
  if (selfIp && ip === selfIp) return false
  return true
}

/** Inline ban button for IP cells in the log tables. Hidden for loopback /
 *  own-IP entries; disables itself after a successful ban. */
function BanIpButton({ ip, selfIp, __t: t, flash }) {
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)
  if (!canBanIp(ip, selfIp)) return null
  return h('button', {
    className: 'um-btn um-btn-danger',
    style: { marginLeft: 6, padding: '0 7px', fontSize: 11, lineHeight: '18px' },
    disabled: busy || done,
    title: interpolate(t('banConfirm'), { ip }),
    onClick: () => {
      if (!window.confirm(interpolate(t('banConfirm'), { ip }))) return
      setBusy(true)
      api('/bans', { method: 'POST', body: { ip, note: '' } })
        .then(() => { flash(t('banned')); setDone(true) })
        .catch((e) => flash(t('failed') + e.message))
        .finally(() => setBusy(false))
    },
  }, done ? t('bannedShort') : t('banAction'))
}

// ── styles ────────────────────────────────────────────────────────────────

const STYLE = `
.um-wrap { font-size: 13px; color: var(--dsw-alias-label-primary); display: flex; flex-direction: column; gap: 14px; }
.um-avatar { border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; color: rgba(255,255,255,.95); font-weight: 600; flex: none; user-select: none; letter-spacing: 0; }
.um-brand-name { font-size: 13px; font-weight: 600; color: var(--dsw-alias-label-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: block; max-width: 150px; }
.um-logout { display: inline-flex; align-items: center; gap: 6px; border: 0; background: transparent; color: var(--dsw-alias-label-secondary); font-size: 12px; padding: 6px 10px; border-radius: 7px; cursor: pointer; flex: none; }
.um-logout:hover { background: var(--dsw-alias-interactive-bg-hover); color: var(--dsw-alias-state-error-primary); }
.um-user-menu { min-width: 216px; background: var(--dsw-alias-bg-layer-1); border: 1px solid var(--dsw-alias-border-l2); border-radius: 10px; box-shadow: 0 8px 28px rgba(0,0,0,.18); padding: 6px; }
.um-user-menu-head { display: flex; align-items: center; gap: 10px; padding: 8px 10px; }
.um-user-menu-name { font-size: 13px; font-weight: 600; color: var(--dsw-alias-label-primary); line-height: 1.3; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.um-user-menu-sep { height: 1px; background: var(--dsw-alias-border-l1); margin: 4px 6px; }
.um-user-menu-item { display: flex; align-items: center; gap: 8px; width: 100%; border: 0; background: transparent; color: var(--dsw-alias-label-primary); font-size: 12.5px; padding: 8px 10px; border-radius: 7px; cursor: pointer; text-align: left; }
.um-user-menu-item:hover { background: var(--dsw-alias-interactive-bg-hover); }
.um-user-menu-logout { color: var(--dsw-alias-state-error-primary); }
.um-user-menu-logout:hover { background: color-mix(in srgb, var(--dsw-alias-state-error-primary) 10%, transparent); }
.um-card { background: var(--dsw-alias-bg-layer-1); border: 1px solid var(--dsw-alias-border-l1); border-radius: 10px; padding: 14px 16px; }
.um-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.um-title { font-size: 14px; font-weight: 600; margin: 0; }
.um-muted { color: var(--dsw-alias-label-secondary); }
.um-btn { border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); border-radius: 7px; padding: 4px 10px; font-size: 12px; cursor: pointer; }
.um-btn:hover { background: var(--dsw-alias-interactive-bg-hover); }
.um-btn:disabled { opacity: .45; cursor: default; }
.um-btn-primary { background: var(--dsw-alias-state-business-primary); border-color: transparent; color: var(--dsw-alias-label-primary-inverted, #fff); }
.um-btn-danger { color: var(--dsw-alias-state-error-primary); }
.um-tabs { display: flex; gap: 4px; background: var(--dsw-alias-bg-layer-2); border-radius: 8px; padding: 3px; width: max-content; }
.um-tab { border: 0; background: transparent; color: var(--dsw-alias-label-secondary); border-radius: 6px; padding: 5px 12px; font-size: 12px; cursor: pointer; }
.um-tab.active { background: var(--dsw-alias-bg-layer-1); color: var(--dsw-alias-label-primary); }
.um-table-wrap { border: 1px solid var(--dsw-alias-border-l2); border-radius: 10px; overflow: auto; background: var(--dsw-alias-bg-layer-1); box-shadow: 0 1px 2px rgba(0,0,0,.05); }
.um-table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 12.5px; }
.um-table th { text-align: left; font-size: 11px; font-weight: 600; letter-spacing: .04em; color: var(--dsw-alias-label-secondary); background: var(--dsw-alias-bg-layer-2); padding: 8px 12px; white-space: nowrap; border-bottom: 1px solid var(--dsw-alias-border-l2); position: sticky; top: 0; z-index: 1; }
.um-table td { padding: 8px 12px; border-bottom: 1px solid var(--dsw-alias-border-l2); vertical-align: middle; color: var(--dsw-alias-label-primary); }
.um-table tbody tr:last-child td { border-bottom: 0; }
.um-table tbody tr:hover { background: var(--dsw-alias-interactive-bg-hover); }
.um-empty { padding: 26px 0; text-align: center; color: var(--dsw-alias-label-tertiary); font-size: 12.5px; }
.um-badge { display: inline-block; font-size: 11px; line-height: 1.5; border-radius: 999px; padding: 1px 8px; border: 1px solid var(--dsw-alias-border-l2); color: var(--dsw-alias-label-secondary); }
.um-badge-admin { color: var(--dsw-alias-state-business-primary); border-color: var(--dsw-alias-state-business-primary); background: color-mix(in srgb, var(--dsw-alias-state-business-primary) 10%, transparent); }
.um-badge-ok { color: var(--dsw-alias-state-success-primary); border-color: var(--dsw-alias-state-success-primary); background: color-mix(in srgb, var(--dsw-alias-state-success-primary) 10%, transparent); }
.um-badge-err { color: var(--dsw-alias-state-error-primary); border-color: var(--dsw-alias-state-error-primary); background: color-mix(in srgb, var(--dsw-alias-state-error-primary) 12%, transparent); }
.um-input { border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); border-radius: 7px; padding: 5px 9px; font-size: 12px; outline: none; }
.um-input:focus { border-color: var(--dsw-alias-state-business-primary); }
.um-form { display: flex; flex-direction: column; gap: 8px; max-width: 340px; }
.um-form label { font-size: 12px; color: var(--dsw-alias-label-secondary); }
.um-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.um-toast { position: fixed; left: 50%; bottom: 28px; transform: translateX(-50%); background: var(--dsw-alias-bg-layer-3); color: var(--dsw-alias-label-primary); border: 1px solid var(--dsw-alias-border-l2); border-radius: 8px; padding: 8px 16px; font-size: 12px; z-index: 60; box-shadow: 0 4px 16px rgba(0,0,0,.18); }
.um-dlg-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,.45); display: flex; align-items: center; justify-content: center; z-index: 55; }
.um-dlg { background: var(--dsw-alias-bg-layer-1); border: 1px solid var(--dsw-alias-border-l2); border-radius: 12px; padding: 18px 20px; width: 420px; max-width: 92vw; box-shadow: 0 10px 40px rgba(0,0,0,.25); }
.um-dlg h3 { margin: 0 0 10px; font-size: 14px; }
.um-temp-pwd { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 15px; background: var(--dsw-alias-bg-layer-2); border: 1px dashed var(--dsw-alias-border-l2); border-radius: 8px; padding: 10px 12px; margin: 10px 0; text-align: center; user-select: all; }
.um-dlg-foot { display: flex; justify-content: flex-end; gap: 8px; margin-top: 12px; }
.um-kv { display: grid; grid-template-columns: 96px 1fr; gap: 6px 12px; font-size: 13px; }
.um-kv dt { color: var(--dsw-alias-label-secondary); }
.um-kv dd { margin: 0; }
`

function ensureStyles() {
  if (typeof document === 'undefined' || document.getElementById('um-styles')) return
  // Must be a real <style> element — CSS text inside a <div> never applies.
  const el = document.createElement('style')
  el.id = 'um-styles'
  el.textContent = STYLE
  document.head.appendChild(el)
}

/** Self-drawn dialog: the host Modal portals to <body> with a z-index below
 *  full pages, so settings-section surfaces must draw their own. */
function UmDialog({ title, onClose, children, footer }) {
  return h('div', { className: 'um-dlg-backdrop', onClick: onClose },
    h('div', { className: 'um-dlg', onClick: (e) => e.stopPropagation() },
      title && h('h3', null, title),
      children,
      footer && h('div', { className: 'um-dlg-foot' }, footer)))
}

// ── sidebar brand (avatar + username, top-left) ───────────────────────────

/** Module-level session cache: the brand row and the settings section share
 *  one /session fetch per page load. undefined = loading, null = signed out. */
const sessionCache = { me: undefined }
function loadMeCached() {
  if (sessionCache.me !== undefined) return Promise.resolve(sessionCache.me)
  return api('/session').then((d) => { sessionCache.me = d.user; return d.user })
    .catch(() => { sessionCache.me = null; return null })
}

function avatarHue(username) {
  let hash = 0
  for (const ch of String(username || '?')) hash = (hash * 31 + ch.codePointAt(0)) % 360
  return hash
}

/** Initial-letter avatar: deterministic hue per username, theme-safe. */
function UserAvatar({ username, size = 22 }) {
  const label = String(username || '?')
  return h('div', {
    className: 'um-avatar',
    title: label,
    style: {
      width: size,
      height: size,
      fontSize: Math.max(10, Math.round(size * 0.44)),
      background: `hsl(${avatarHue(label)}, 42%, 46%)`,
    },
  }, label.charAt(0).toUpperCase())
}

/** Sidebar brand mark — host renders it in the expanded brand row AND the
 *  collapsed rail (owner supplies the square `size`), so fold states adapt
 *  without us tracking the shell. Clicking it (or the name) opens the
 *  user menu; sign-out sits at the bottom in red. */
function BrandMark({ size, className }) {
  useEffect(ensureStyles, [])
  const [me, setMe] = useState(sessionCache.me)
  useEffect(() => { loadMeCached().then((user) => setMe(user)) }, [])
  const { toggle, menu, dialog } = useUserMenu(me)
  if (!me) {
    return h('div', { className, style: { width: size, height: size, borderRadius: '50%', background: 'var(--dsw-alias-bg-layer-3)' } })
  }
  return h('div', {
    className,
    style: { cursor: 'pointer', display: 'inline-flex', borderRadius: '50%' },
    title: me.username,
    'aria-haspopup': 'menu',
    onClick: toggle,
  },
    h(UserAvatar, { username: me.username, size: size || 24 }),
    menu,
    dialog)
}

/** Sidebar brand name — host renders it beside the expanded mark only. */
function BrandName() {
  useEffect(ensureStyles, [])
  const [me, setMe] = useState(sessionCache.me)
  useEffect(() => { loadMeCached().then((user) => setMe(user)) }, [])
  const { toggle, menu, dialog } = useUserMenu(me)
  return h('span', {
    className: 'um-brand-name',
    style: { cursor: 'pointer' },
    title: me ? me.username : '',
    'aria-haspopup': 'menu',
    onClick: toggle,
  }, me ? me.username : '', menu, dialog)
}

// ── logout ────────────────────────────────────────────────────────────────

/** Locale accessor for slot components living outside apply()'s closure —
 *  updated when apply() binds the real dictionary; zh until then. */
let localeT = (key) => ZH[key] || key

function doLogout() {
  // clearing the session makes the gate bounce the next navigation to /login
  api('/logout', { method: 'POST' }).catch(() => {}).finally(() => { location.href = '/login' })
}

function PowerIcon({ size = 14 }) {
  return h('svg', { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'aria-hidden': 'true' },
    h('path', { d: 'M18.36 6.64a9 9 0 1 1-12.73 0' }),
    h('line', { x1: 12, y1: 2, x2: 12, y2: 12 }))
}

function KeyIcon({ size = 14 }) {
  return h('svg', { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' },
    h('path', { d: 'M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4' }))
}

function LogoutButton({ withLabel, __t: t }) {
  useEffect(ensureStyles, [])
  return h('button', {
    className: 'um-logout',
    title: t('actionLogout'),
    'aria-label': t('actionLogout'),
    onClick: doLogout,
  }, PowerIcon(), withLabel ? t('actionLogout') : null)
}

/** Self-service password change — the admin panel has no inline form
 *  (MyPanel's one is for plain users), so this dialog is the shared
 *  entry from the user menu. Portaled to <body> like the user menu. */
function ChangePasswordDialog({ onClose, __t: t }) {
  const [oldPwd, setOldPwd] = useState('')
  const [newPwd, setNewPwd] = useState('')
  const [confirmPwd, setConfirmPwd] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [done, setDone] = useState(false)

  const submit = (e) => {
    e.preventDefault()
    if (newPwd !== confirmPwd) { setErr(t('pwdMismatch')); return }
    setBusy(true)
    setErr('')
    api('/me/password', { method: 'POST', body: { oldPassword: oldPwd, newPassword: newPwd } })
      .then(() => { setDone(true); setTimeout(onClose, 1200) })
      .catch((e2) => setErr(String(e2 && e2.message)))
      .finally(() => setBusy(false))
  }

  const dialog = h(UmDialog, {
    title: t('changePwd'), onClose,
    footer: [
      h('button', { className: 'um-btn', onClick: onClose }, '✕'),
      h('button', { className: 'um-btn um-btn-primary', onClick: submit, disabled: busy || done }, t('save')),
    ],
  },
    done
      ? h('div', { style: { color: 'var(--dsw-alias-state-success-primary)', fontSize: 13, padding: '6px 0' } }, t('pwdChanged'))
      : h('form', { className: 'um-form', onSubmit: submit, style: { maxWidth: 'none' } },
        h('label', { htmlFor: 'um-cp-old' }, t('oldPwd')),
        h('input', { id: 'um-cp-old', className: 'um-input', type: 'password', autoComplete: 'current-password', value: oldPwd, onChange: (e) => setOldPwd(e.target.value), required: true, autoFocus: true }),
        h('label', { htmlFor: 'um-cp-new' }, t('newPwd')),
        h('input', { id: 'um-cp-new', className: 'um-input', type: 'password', autoComplete: 'new-password', minLength: 6, value: newPwd, onChange: (e) => setNewPwd(e.target.value), required: true }),
        h('label', { htmlFor: 'um-cp-conf' }, t('confirmPwd')),
        h('input', { id: 'um-cp-conf', className: 'um-input', type: 'password', autoComplete: 'new-password', value: confirmPwd, onChange: (e) => setConfirmPwd(e.target.value), required: true }),
        err && h('div', { style: { color: 'var(--dsw-alias-state-error-primary)', fontSize: 12 } }, err)))
  return RDP && typeof RDP.createPortal === 'function' ? RDP.createPortal(dialog, document.body) : dialog
}

/** The user menu popped from the brand row: identity header, change
 *  password, separator, and the red sign-out as the last item. Portaled
 *  to <body> so sidebar overflow can't clip it. */
function UserMenu({ anchor, username, role, onClose, onChangePwd }) {
  const ref = useRef(null)
  const t = localeT
  useEffect(() => {
    const onDoc = (e) => {
      if (ref.current && !ref.current.contains(e.target) && anchor && !anchor.contains(e.target)) onClose()
    }
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [anchor, onClose])
  const rect = anchor ? anchor.getBoundingClientRect() : { left: 8, bottom: 8, right: 8 }
  const MENU_WIDTH = 216
  const left = Math.max(8, Math.min(rect.left, window.innerWidth - MENU_WIDTH - 8))
  const style = { position: 'fixed', left, top: rect.bottom + 6, width: MENU_WIDTH }
  return RDP && typeof RDP.createPortal === 'function'
    ? RDP.createPortal(
      h('div', { className: 'um-user-menu', ref, style, role: 'menu' },
        h('div', { className: 'um-user-menu-head' },
          h(UserAvatar, { username, size: 30 }),
          h('div', { style: { minWidth: 0 } },
            h('div', { className: 'um-user-menu-name', title: username }, username),
            h('div', { style: { marginTop: 3 } }, h(RoleBadge, { role, __t: t })))),
        h('div', { className: 'um-user-menu-sep' }),
        h('button', {
          className: 'um-user-menu-item',
          role: 'menuitem',
          onClick: () => { onClose(); onChangePwd() },
        }, KeyIcon(), t('changePwd')),
        h('div', { className: 'um-user-menu-sep' }),
        h('button', {
          className: 'um-user-menu-item um-user-menu-logout',
          role: 'menuitem',
          onClick: () => { onClose(); doLogout() },
        }, PowerIcon(), t('actionLogout'))),
      document.body)
    : null
}

/** Shared click-to-open behaviour for both brand seats. */
function useUserMenu(me) {
  const [anchor, setAnchor] = useState(null)
  const [pwdOpen, setPwdOpen] = useState(false)
  const toggle = (e) => {
    e.stopPropagation()
    // React nulls e.currentTarget after dispatch; the updater may run later,
    // so capture the element first or the anchor silently stays null.
    const target = e.currentTarget
    setAnchor((current) => (current ? null : target))
  }
  const menu = (anchor && me)
    ? h(UserMenu, { anchor, username: me.username, role: me.role, onClose: () => setAnchor(null), onChangePwd: () => setPwdOpen(true) })
    : null
  const dialog = pwdOpen ? h(ChangePasswordDialog, { onClose: () => setPwdOpen(false), __t: localeT }) : null
  return { toggle, menu, dialog }
}

// ── components ────────────────────────────────────────────────────────────

function RoleBadge({ role, __t: t }) {
  return h('span', { className: role === 'admin' ? 'um-badge um-badge-admin' : 'um-badge' },
    role === 'admin' ? t('roleAdmin') : t('roleUser'))
}

function UsersTab({ me, __t: t, flash }) {
  const [users, setUsers] = useState(null)
  const [temp, setTemp] = useState(null) // {name, pwd}
  const [busyId, setBusyId] = useState(null)
  const [copied, setCopied] = useState(false)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({ username: '', password: '', role: 'user' })

  const load = () => api('/users').then((d) => setUsers(d.users)).catch((e) => flash(t('failed') + e.message))
  useEffect(() => { load() }, [])

  const act = async (user, fn) => {
    setBusyId(user.id)
    try { await fn() } catch (e) { flash(t('failed') + e.message) } finally { setBusyId(null) }
  }

  const resetPwd = (user) => {
    if (!window.confirm(interpolate(t('resetPwdConfirm'), { name: user.username }))) return
    act(user, async () => {
      const d = await api(`/users/${user.id}/reset-password`, { method: 'POST' })
      setTemp({ name: user.username, pwd: d.tempPassword })
      setCopied(false)
    })
  }

  const changeRole = (user) => {
    const nextRole = user.role === 'admin' ? 'user' : 'admin'
    const label = nextRole === 'admin' ? t('roleAdmin') : t('roleUser')
    if (!window.confirm(interpolate(t('roleConfirm'), { name: user.username, role: label }))) return
    act(user, async () => {
      await api(`/users/${user.id}/role`, { method: 'POST', body: { role: nextRole } })
      flash(t('opOk'))
      await load()
    })
  }

  const toggleDisabled = (user) => {
    const disabling = !user.disabled
    const key = disabling ? 'disableConfirm' : 'enableConfirm'
    if (!window.confirm(interpolate(t(key), { name: user.username }))) return
    act(user, async () => {
      await api(`/users/${user.id}/disabled`, { method: 'POST', body: { disabled: disabling } })
      flash(t('opOk'))
      await load()
    })
  }

  const remove = (user) => {
    if (!window.confirm(interpolate(t('deleteConfirm'), { name: user.username }))) return
    act(user, async () => {
      await api(`/users/${user.id}`, { method: 'DELETE' })
      flash(t('opOk'))
      await load()
    })
  }

  const submitCreate = (e) => {
    e.preventDefault()
    api('/users', { method: 'POST', body: form })
      .then(() => { setCreating(false); setForm({ username: '', password: '', role: 'user' }); flash(t('userCreated')); return load() })
      .catch((err) => flash(t('failed') + err.message))
  }

  const copyTemp = () => {
    try {
      navigator.clipboard.writeText(temp.pwd).then(() => setCopied(true), () => {})
    } catch { /* clipboard unavailable */ }
  }

  if (users === null) return h('div', { className: 'um-card um-muted' }, t('loading'))

  return h('div', { className: 'um-card' },
    h('div', { className: 'um-head', style: { marginBottom: 10 } },
      h('h3', { className: 'um-title' }, interpolate(t('userCount'), { n: users.length })),
      h('div', { className: 'um-row' },
        h('button', { className: 'um-btn um-btn-primary', onClick: () => setCreating(true) }, t('createUser')),
        h('button', { className: 'um-btn', onClick: load }, t('reload')))),
    h('div', { className: 'um-table-wrap' },
      h('table', { className: 'um-table' },
        h('thead', null, h('tr', null,
          h('th', null, t('colUser')),
          h('th', null, t('colRole')),
          h('th', null, t('colCreatedAt')),
          h('th', null, t('colLastLogin')),
          h('th', null, ''))),
        h('tbody', null, users.map((user) => h('tr', { key: user.id, style: user.disabled ? { opacity: 0.55 } : undefined },
          h('td', null, user.username, user.id === me.id ? t('you') : null),
          h('td', null, h('span', { className: 'um-row', style: { gap: 4 } },
            h(RoleBadge, { role: user.role, __t: t }),
            user.disabled ? h('span', { className: 'um-badge um-badge-err' }, t('badgeDisabled')) : null)),
          h('td', { className: 'um-muted' }, formatTime(user.createdAt)),
          h('td', { className: 'um-muted' }, formatTime(user.lastLoginAt)),
          h('td', null, h('div', { className: 'um-row', style: { justifyContent: 'flex-end' } },
            h('button', { className: 'um-btn', disabled: busyId === user.id, onClick: () => resetPwd(user) }, t('actionResetPwd')),
            h('button', {
              className: 'um-btn', disabled: busyId === user.id || user.id === me.id,
              title: user.id === me.id ? '-' : undefined, onClick: () => changeRole(user),
            }, user.role === 'admin' ? t('actionSetUser') : t('actionSetAdmin')),
            h('button', {
              className: user.disabled ? 'um-btn' : 'um-btn um-btn-danger',
              disabled: busyId === user.id || user.id === me.id,
              title: user.id === me.id ? '-' : undefined,
              onClick: () => toggleDisabled(user),
            }, user.disabled ? t('actionEnable') : t('actionDisable')),
            h('button', {
              className: 'um-btn um-btn-danger', disabled: busyId === user.id || user.id === me.id,
              onClick: () => remove(user),
            }, t('actionDelete'))))))))),
    creating && h(UmDialog, {
      title: t('createUserTitle'), onClose: () => setCreating(false),
      footer: [
        h('button', { className: 'um-btn', onClick: () => setCreating(false) }, '✕'),
        h('button', { className: 'um-btn um-btn-primary', onClick: submitCreate }, t('submitCreate')),
      ],
    },
      h('form', { className: 'um-form', onSubmit: submitCreate },
        h('label', { htmlFor: 'um-new-username' }, t('colUser')),
        h('input', { id: 'um-new-username', className: 'um-input', value: form.username, onChange: (e) => setForm({ ...form, username: e.target.value }), required: true, autoFocus: true }),
        h('label', { htmlFor: 'um-new-password' }, t('colPassword')),
        h('input', { id: 'um-new-password', className: 'um-input', type: 'password', autoComplete: 'new-password', minLength: 6, value: form.password, onChange: (e) => setForm({ ...form, password: e.target.value }), required: true }),
        h('label', { htmlFor: 'um-new-role' }, t('colRolePick')),
        h('select', { id: 'um-new-role', className: 'um-input', value: form.role, onChange: (e) => setForm({ ...form, role: e.target.value }) },
          h('option', { value: 'user' }, t('roleUser')),
          h('option', { value: 'admin' }, t('roleAdmin'))))),
    temp && h(UmDialog, {
      title: t('tempPwdTitle'), onClose: () => setTemp(null),
      footer: [
        h('button', { className: 'um-btn', onClick: copyTemp }, copied ? t('copied') : t('copy')),
        h('button', { className: 'um-btn um-btn-primary', onClick: () => setTemp(null) }, 'OK'),
      ],
    },
      h('p', { className: 'um-muted', style: { margin: 0 } }, interpolate(t('tempPwdHint'), { name: temp.name })),
      h('div', { className: 'um-temp-pwd' }, temp.pwd)))
}

function ActivityTab({ kind, __t: t, flash }) {
  const [entries, setEntries] = useState(null)
  const [username, setUsername] = useState('')
  const [type, setType] = useState('')
  const [selfIp, setSelfIp] = useState('')

  const load = () => api('/activity?limit=200').then((d) => setEntries(d.entries)).catch((e) => setEntries([]) /* flash handled by empty state */)
  useEffect(() => {
    load()
    api('/bans').then((d) => setSelfIp(d.selfIp)).catch(() => {})
  }, [])

  const visible = useMemo(
    () => filterActivity(entries, { username: username.trim() || null, type: type || null })
      .filter((entry) => (kind === 'accessLog' ? entry.type === 'access' : entry.type !== 'access')),
    [entries, username, type, kind])

  return h('div', { className: 'um-card' },
    h('div', { className: 'um-head', style: { marginBottom: 10 } },
      h('div', { className: 'um-row' },
        h('input', { className: 'um-input', placeholder: t('filterUser'), value: username, onChange: (e) => setUsername(e.target.value) }),
        kind === 'loginLog' && h('select', { className: 'um-input', value: type, onChange: (e) => setType(e.target.value) },
          h('option', { value: '' }, t('filterAll')),
          Object.entries(TYPE_LABELS).filter(([key]) => key !== 'access').map(([key, labelKey]) =>
            h('option', { key, value: key }, t(labelKey))))),
      h('button', { className: 'um-btn', onClick: load }, t('reload'))),
    entries === null
      ? h('div', { className: 'um-muted' }, t('loading'))
      : visible.length === 0
        ? h('div', { className: 'um-empty' }, t('empty'))
        : h('div', { className: 'um-table-wrap' },
          h('table', { className: 'um-table' },
            h('thead', null, h('tr', null,
              h('th', null, t('colTime')),
              h('th', null, t('colType')),
              h('th', null, t('colUser')),
              h('th', null, t('colIp')),
              h('th', null, t('colDetail')))),
            h('tbody', null, visible.map((entry, i) => h('tr', { key: i },
              h('td', { className: 'um-muted', style: { whiteSpace: 'nowrap' } }, formatTime(entry.ts)),
              h('td', null, t(TYPE_LABELS[entry.type] || entry.type)),
              h('td', null, entry.username || '-'),
              h('td', { className: 'um-muted', style: { whiteSpace: 'nowrap' } }, entry.ip || '-',
                h(BanIpButton, { ip: entry.ip, selfIp, __t: t, flash })),
              h('td', { className: 'um-muted' }, entry.detail || '-')))))))
}

/** Admin-only operation audit: every gated API call / WS connection with
 *  its response status, filterable by username, method, path and status.
 *  Rows can be deleted individually; the whole ledger can be cleared. */
function AuditTab({ __t: t, flash }) {
  const [entries, setEntries] = useState(null)
  const [username, setUsername] = useState('')
  const [method, setMethod] = useState('')
  const [path, setPath] = useState('')
  const [statusClass, setStatusClass] = useState('')
  const [busyId, setBusyId] = useState(null)
  const [selfIp, setSelfIp] = useState('')

  const load = () => api('/audit?limit=500').then((d) => setEntries(d.entries)).catch(() => setEntries([]))
  useEffect(() => {
    load()
    api('/bans').then((d) => setSelfIp(d.selfIp)).catch(() => {})
  }, [])

  const del = (entry) => {
    if (!window.confirm(t('delEntryConfirm'))) return
    setBusyId(entry.id)
    api(`/audit/${entry.id}`, { method: 'DELETE' })
      .then(() => { flash(t('entryDeleted')); return load() })
      .catch((e) => flash(t('failed') + e.message))
      .finally(() => setBusyId(null))
  }

  const clearAll = () => {
    if (!window.confirm(t('clearLogConfirm'))) return
    api('/audit', { method: 'DELETE' })
      .then(() => { flash(t('auditCleared')); return load() })
      .catch((e) => flash(t('failed') + e.message))
  }

  const visible = useMemo(
    () => filterAudit(entries, { username: username.trim() || null, method: method || null, path: path.trim() || null, statusClass: statusClass || null }),
    [entries, username, method, path, statusClass])

  const statusBadge = (status) => {
    const cls = status >= 500 ? 'um-badge um-badge-err' : status >= 400 ? 'um-badge um-badge-err' : 'um-badge um-badge-ok'
    return h('span', { className: cls }, status ?? '-')
  }

  return h('div', { className: 'um-card' },
    h('div', { className: 'um-head', style: { marginBottom: 10 } },
      h('div', { className: 'um-row' },
        h('input', { className: 'um-input', placeholder: t('filterUser'), value: username, onChange: (e) => setUsername(e.target.value) }),
        h('select', { className: 'um-input', value: method, onChange: (e) => setMethod(e.target.value) },
          h('option', { value: '' }, t('filterAll')),
          ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'WS'].map((m) => h('option', { key: m, value: m }, m))),
        h('input', { className: 'um-input', placeholder: t('filterPath'), value: path, onChange: (e) => setPath(e.target.value) }),
        h('select', { className: 'um-input', value: statusClass, onChange: (e) => setStatusClass(e.target.value) },
          h('option', { value: '' }, t('statusAll')),
          h('option', { value: '2' }, t('statusOk')),
          h('option', { value: '4' }, t('statusErr')),
          h('option', { value: '5' }, t('statusErr')))),
      h('div', { className: 'um-row' },
        h('button', { className: 'um-btn', onClick: load }, t('reload')),
        h('button', { className: 'um-btn um-btn-danger', disabled: !entries || entries.length === 0, onClick: clearAll }, t('clearLog')))),
    entries === null
      ? h('div', { className: 'um-muted' }, t('loading'))
      : visible.length === 0
        ? h('div', { className: 'um-empty' }, t('empty'))
        : h('div', { className: 'um-table-wrap' },
          h('table', { className: 'um-table' },
            h('thead', null, h('tr', null,
              h('th', null, t('colTime')),
              h('th', null, t('colMethod')),
              h('th', null, t('colPath')),
              h('th', null, t('colUser')),
              h('th', null, t('colIp')),
              h('th', null, t('colStatus')),
              h('th', null, ''))),
            h('tbody', null, visible.map((entry, i) => h('tr', { key: i },
              h('td', { className: 'um-muted', style: { whiteSpace: 'nowrap' } }, formatTime(entry.ts)),
              h('td', null, entry.type === 'ws' ? t('typeWsConn') : entry.method || '-'),
              h('td', { className: 'um-muted', style: { wordBreak: 'break-all' } }, entry.path || '-'),
              h('td', null, entry.username || '-'),
              h('td', null, entry.ip || '-', h(BanIpButton, { ip: entry.ip, selfIp, __t: t, flash })),
              h('td', null, entry.type === 'ws' ? h('span', { className: 'um-badge' }, t('typeWsConn')) : statusBadge(entry.status)),
              h('td', null, h('button', {
                className: 'um-btn um-btn-danger', disabled: busyId === entry.id,
                onClick: () => del(entry),
              }, t('actionDelete')))))))))
}

/** Admin-only IP bans: gate-level deny list checked before sessions —
 *  banned addresses can't even load the login page. */
function BansTab({ __t: t, flash }) {
  const [bans, setBans] = useState(null)
  const [ip, setIp] = useState('')
  const [note, setNote] = useState('')
  const [selfIp, setSelfIp] = useState('')
  const [busy, setBusy] = useState(false)

  const load = () => api('/bans').then((d) => { setBans(d.bans); setSelfIp(d.selfIp) }).catch(() => setBans([]))
  useEffect(() => { load() }, [])

  const ban = (e) => {
    e.preventDefault()
    const target = ip.trim()
    if (!target) return
    if (!window.confirm(interpolate(t('banConfirm'), { ip: target }))) return
    setBusy(true)
    api('/bans', { method: 'POST', body: { ip: target, note: note.trim() } })
      .then(() => { flash(t('banned')); setIp(''); setNote(''); return load() })
      .catch((err) => flash(t('failed') + err.message))
      .finally(() => setBusy(false))
  }

  const unban = (entry) => {
    if (!window.confirm(interpolate(t('unbanConfirm'), { ip: entry.ip }))) return
    api(`/bans/${encodeURIComponent(entry.ip)}`, { method: 'DELETE' })
      .then(() => { flash(t('unbanned')); return load() })
      .catch((err) => flash(t('failed') + err.message))
  }

  return h('div', { className: 'um-card' },
    h('form', { className: 'um-row', style: { marginBottom: 10 }, onSubmit: ban },
      h('input', { className: 'um-input', placeholder: t('banIpPlaceholder'), value: ip, onChange: (e) => setIp(e.target.value), required: true, style: { width: 220 } }),
      h('input', { className: 'um-input', placeholder: t('banNotePlaceholder'), value: note, onChange: (e) => setNote(e.target.value), style: { width: 200 } }),
      h('button', { className: 'um-btn um-btn-danger', type: 'submit', disabled: busy }, t('banAction'))),
    bans === null
      ? h('div', { className: 'um-muted' }, t('loading'))
      : bans.length === 0
        ? h('div', { className: 'um-empty' }, t('empty'))
        : h('div', { className: 'um-table-wrap' },
          h('table', { className: 'um-table' },
            h('thead', null, h('tr', null,
              h('th', null, 'IP'),
              h('th', null, t('colNote')),
              h('th', null, t('colBannedBy')),
              h('th', null, t('colTime')),
              h('th', null, ''))),
            h('tbody', null, bans.map((entry) => h('tr', { key: entry.ip },
              h('td', null, entry.ip, entry.ip === selfIp ? h('span', { className: 'um-muted' }, t('selfIp')) : null),
              h('td', { className: 'um-muted' }, entry.note || '-'),
              h('td', null, entry.createdBy || '-'),
              h('td', { className: 'um-muted', style: { whiteSpace: 'nowrap' } }, formatTime(entry.createdAt)),
              h('td', null, h('button', { className: 'um-btn um-btn-danger', onClick: () => unban(entry) }, t('unbanAction')))))))))
}

function MyPanel({ me, __t: t, flash }) {
  const [oldPwd, setOldPwd] = useState('')
  const [newPwd, setNewPwd] = useState('')
  const [confirmPwd, setConfirmPwd] = useState('')
  const [busy, setBusy] = useState(false)
  const [entries, setEntries] = useState(null)

  useEffect(() => { api('/activity?limit=50').then((d) => setEntries(d.entries)).catch(() => setEntries([])) }, [])

  const submit = (e) => {
    e.preventDefault()
    if (newPwd !== confirmPwd) { flash(t('pwdMismatch')); return }
    setBusy(true)
    api('/me/password', { method: 'POST', body: { oldPassword: oldPwd, newPassword: newPwd } })
      .then(() => { flash(t('pwdChanged')); setOldPwd(''); setNewPwd(''); setConfirmPwd('') })
      .catch((err) => flash(t('failed') + err.message))
      .finally(() => setBusy(false))
  }

  return h('div', { style: { display: 'flex', flexDirection: 'column', gap: 14 } },
    h('div', { className: 'um-card' },
      h('div', { className: 'um-head' },
        h('h3', { className: 'um-title' }, t('myInfo')),
        h(LogoutButton, { withLabel: true, __t: t })),
      h('dl', { className: 'um-kv', style: { marginTop: 10 } },
        h('dt', null, t('colUser')), h('dd', null, me.username),
        h('dt', null, t('colRole')), h('dd', null, h(RoleBadge, { role: me.role, __t: t })),
        h('dt', null, t('colCreatedAt')), h('dd', null, formatTime(me.createdAt)),
        h('dt', null, t('colLastLogin')), h('dd', null, formatTime(me.lastLoginAt)))),
    h('form', { className: 'um-card um-form', onSubmit: submit },
      h('h3', { className: 'um-title' }, t('changePwd')),
      h('label', { htmlFor: 'um-old-pwd' }, t('oldPwd')),
      h('input', { id: 'um-old-pwd', className: 'um-input', type: 'password', autoComplete: 'current-password', value: oldPwd, onChange: (e) => setOldPwd(e.target.value), required: true }),
      h('label', { htmlFor: 'um-new-pwd' }, t('newPwd')),
      h('input', { id: 'um-new-pwd', className: 'um-input', type: 'password', autoComplete: 'new-password', value: newPwd, onChange: (e) => setNewPwd(e.target.value), required: true, minLength: 6 }),
      h('label', { htmlFor: 'um-conf-pwd' }, t('confirmPwd')),
      h('input', { id: 'um-conf-pwd', className: 'um-input', type: 'password', autoComplete: 'new-password', value: confirmPwd, onChange: (e) => setConfirmPwd(e.target.value), required: true }),
      h('div', null, h('button', { className: 'um-btn um-btn-primary', type: 'submit', disabled: busy }, t('save')))),
    h('div', { className: 'um-card' },
      h('h3', { className: 'um-title', style: { marginBottom: 10 } }, t('tabLoginLog')),
      entries === null
        ? h('div', { className: 'um-muted' }, t('loading'))
        : entries.length === 0
          ? h('div', { className: 'um-empty' }, t('empty'))
          : h('div', { className: 'um-table-wrap' },
            h('table', { className: 'um-table' },
              h('thead', null, h('tr', null,
                h('th', null, t('colTime')),
                h('th', null, t('colType')),
                h('th', null, t('colIp')))),
              h('tbody', null, entries.map((entry, i) => h('tr', { key: i },
                h('td', { className: 'um-muted', style: { whiteSpace: 'nowrap' } }, formatTime(entry.ts)),
                h('td', null, t(TYPE_LABELS[entry.type] || entry.type)),
                h('td', { className: 'um-muted' }, entry.ip || '-'))))))))
}

function UserManagementSection({ __t: t }) {
  useEffect(ensureStyles, [])
  const [me, setMe] = useState(undefined) // undefined = loading, null = signed out
  const [toast, setToast] = useState('')
  const toastTimer = useRef(null)
  const flash = (msg) => {
    setToast(msg)
    if (toastTimer.current) clearTimeout(toastTimer.current)
    toastTimer.current = setTimeout(() => setToast(''), 2400)
  }
  useEffect(() => {
    loadMeCached().then((user) => setMe(user))
  }, [])

  return h('div', { className: 'um-wrap' },
    toast && h('div', { className: 'um-toast' }, toast),
    me === undefined && h('div', { className: 'um-card um-muted' }, t('loading')),
    me === null && h('div', { className: 'um-card um-muted' }, t('notLoggedIn')),
    me && (me.role === 'admin'
      ? h(AdminPanel, { me, __t: t, flash })
      : h(MyPanel, { me, __t: t, flash })))
}

function AdminPanel({ me, __t: t, flash }) {
  const [tab, setTab] = useState('users')
  const tabs = [['users', t('tabUsers')], ['loginLog', t('tabLoginLog')], ['accessLog', t('tabAccessLog')], ['auditLog', t('tabAuditLog')], ['bans', t('tabBans')]]
  return h('div', { style: { display: 'flex', flexDirection: 'column', gap: 12 } },
    h('div', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 } },
      h('div', { className: 'um-tabs' }, tabs.map(([key, label]) =>
        h('button', { key, className: tab === key ? 'um-tab active' : 'um-tab', onClick: () => setTab(key) }, label))),
      h(LogoutButton, { withLabel: true, __t: t })),
    tab === 'users' ? h(UsersTab, { me, __t: t, flash })
      : tab === 'auditLog' ? h(AuditTab, { __t: t, flash })
        : tab === 'bans' ? h(BansTab, { __t: t, flash })
          : h(ActivityTab, { kind: tab, __t: t, flash }))
}

// ── module wiring ─────────────────────────────────────────────────────────

function __boot(container) {
  if (!RDP || typeof RDP.createRoot !== 'function') return
  RDP.createRoot(container).render(h(UserManagementSection, { __t: (key, vars) => interpolate(ZH[key] || key, vars) }))
}

module.exports = {
  name: CLIENT_NAME,
  inject: ['slots', 'locale'],
  __boot,
  __internals: { NS, ZH, EN, TYPE_LABELS, api, formatTime, interpolate, filterActivity, filterAudit, avatarHue, UserAvatar, BrandMark, BrandName, canBanIp, BanIpButton, ChangePasswordDialog, UserMenu },
  apply(ctx) {
    ctx.locale.register(NS, 'zh', ZH)
    ctx.locale.register(NS, 'en', EN)
    const t = ctx.locale.bind(NS)
    localeT = t
    ctx.effect(() => {
      // Official-brand pattern: nested injects claim both brand seats, one
      // generator registers them. The mark shows in expanded row + collapsed
      // rail (fold-adaptive), the name only beside the expanded mark.
      // priority: -1 shadows the host's default brand registration at 0
      // ("lowest renders"); uninstalling this plugin restores the official
      // brand with no residue.
      ctx.slots.inject('sidebar.brand.mark', () => ctx.slots.inject('sidebar.brand.name', function* () {
        yield ctx.slots.register({ name: 'sidebar.brand.mark', priority: -1 }, BrandMark)
        yield ctx.slots.register({ name: 'sidebar.brand.name', priority: -1 }, BrandName)
      }))
    }, 'user-management: sidebar brand')
    ctx.effect(() => {
      ctx.slots.inject('settings.section', () => ctx.slots.register({
        name: 'settings.section',
        id: CLIENT_NAME,
        order: 92,
        locale: NS,
        label: () => t('title'),
        inject: () => ({}),
      }, function UserManagementSlot() {
        return h(UserManagementSection, { __t: t })
      }))
    }, 'user-management: settings section')
  },
}
