/* Generated from client/index.js by scripts/build-client.mjs — do not edit by hand.
 * Regenerate with: npm run build:client
 */
window.__ModuleLoader__.load({
  id: "@weibaohui/user-management",
  factory: (require) => {
    var module = { exports: {} }
    var exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" })
    var React = require("react")
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

    // ── styles ────────────────────────────────────────────────────────────────

    const STYLE = `
    .um-wrap { font-size: 13px; color: var(--dsw-alias-label-primary); display: flex; flex-direction: column; gap: 14px; }
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
    .um-table { width: 100%; border-collapse: collapse; }
    .um-table th { text-align: left; font-size: 11px; font-weight: 500; color: var(--dsw-alias-label-tertiary); padding: 6px 8px; border-bottom: 1px solid var(--dsw-alias-border-l1); white-space: nowrap; }
    .um-table td { padding: 7px 8px; border-bottom: 1px solid var(--dsw-alias-border-l1); vertical-align: middle; }
    .um-table tr:last-child td { border-bottom: 0; }
    .um-badge { display: inline-block; font-size: 11px; border-radius: 5px; padding: 1px 7px; border: 1px solid var(--dsw-alias-border-l2); color: var(--dsw-alias-label-secondary); }
    .um-badge-admin { color: var(--dsw-alias-state-business-primary); border-color: var(--dsw-alias-state-business-primary); }
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
      const holder = document.createElement('div')
      holder.id = 'um-styles'
      holder.style.display = 'none'
      holder.innerHTML = STYLE
      document.head.appendChild(holder)
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

      const remove = (user) => {
        if (!window.confirm(interpolate(t('deleteConfirm'), { name: user.username }))) return
        act(user, async () => {
          await api(`/users/${user.id}`, { method: 'DELETE' })
          flash(t('opOk'))
          await load()
        })
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
          h('button', { className: 'um-btn', onClick: load }, t('reload'))),
        h('table', { className: 'um-table' },
          h('thead', null, h('tr', null,
            h('th', null, t('colUser')),
            h('th', null, t('colRole')),
            h('th', null, t('colCreatedAt')),
            h('th', null, t('colLastLogin')),
            h('th', null, ''))),
          h('tbody', null, users.map((user) => h('tr', { key: user.id },
            h('td', null, user.username, user.id === me.id ? t('you') : null),
            h('td', null, h(RoleBadge, { role: user.role, __t: t })),
            h('td', { className: 'um-muted' }, formatTime(user.createdAt)),
            h('td', { className: 'um-muted' }, formatTime(user.lastLoginAt)),
            h('td', null, h('div', { className: 'um-row', style: { justifyContent: 'flex-end' } },
              h('button', { className: 'um-btn', disabled: busyId === user.id, onClick: () => resetPwd(user) }, t('actionResetPwd')),
              h('button', {
                className: 'um-btn', disabled: busyId === user.id || user.id === me.id,
                title: user.id === me.id ? '-' : undefined, onClick: () => changeRole(user),
              }, user.role === 'admin' ? t('actionSetUser') : t('actionSetAdmin')),
              h('button', {
                className: 'um-btn um-btn-danger', disabled: busyId === user.id || user.id === me.id,
                onClick: () => remove(user),
              }, t('actionDelete')))))))),
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

    function ActivityTab({ kind, __t: t }) {
      const [entries, setEntries] = useState(null)
      const [username, setUsername] = useState('')
      const [type, setType] = useState('')

      const load = () => api('/activity?limit=200').then((d) => setEntries(d.entries)).catch((e) => setEntries([]) /* flash handled by empty state */)
      useEffect(() => { load() }, [])

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
            ? h('div', { className: 'um-muted' }, t('empty'))
            : h('table', { className: 'um-table' },
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
                h('td', { className: 'um-muted' }, entry.ip || '-'),
                h('td', { className: 'um-muted' }, entry.detail || '-'))))))
    }

    /** Admin-only operation audit: every gated API call / WS connection with
     *  its response status, filterable by username, method, path and status. */
    function AuditTab({ __t: t }) {
      const [entries, setEntries] = useState(null)
      const [username, setUsername] = useState('')
      const [method, setMethod] = useState('')
      const [path, setPath] = useState('')
      const [statusClass, setStatusClass] = useState('')

      const load = () => api('/audit?limit=500').then((d) => setEntries(d.entries)).catch(() => setEntries([]))
      useEffect(() => { load() }, [])

      const visible = useMemo(
        () => filterAudit(entries, { username: username.trim() || null, method: method || null, path: path.trim() || null, statusClass: statusClass || null }),
        [entries, username, method, path, statusClass])

      const statusBadge = (status) => {
        const cls = status >= 400 ? 'um-badge um-btn-danger' : 'um-badge'
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
          h('button', { className: 'um-btn', onClick: load }, t('reload'))),
        entries === null
          ? h('div', { className: 'um-muted' }, t('loading'))
          : visible.length === 0
            ? h('div', { className: 'um-muted' }, t('empty'))
            : h('table', { className: 'um-table' },
              h('thead', null, h('tr', null,
                h('th', null, t('colTime')),
                h('th', null, t('colMethod')),
                h('th', null, t('colPath')),
                h('th', null, t('colUser')),
                h('th', null, t('colIp')),
                h('th', null, t('colStatus')))),
              h('tbody', null, visible.map((entry, i) => h('tr', { key: i },
                h('td', { className: 'um-muted', style: { whiteSpace: 'nowrap' } }, formatTime(entry.ts)),
                h('td', null, entry.type === 'ws' ? t('typeWsConn') : entry.method || '-'),
                h('td', { className: 'um-muted', style: { wordBreak: 'break-all' } }, entry.path || '-'),
                h('td', null, entry.username || '-'),
                h('td', { className: 'um-muted' }, entry.ip || '-'),
                h('td', null, entry.type === 'ws' ? h('span', { className: 'um-badge' }, t('typeWsConn')) : statusBadge(entry.status)))))))
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
          h('h3', { className: 'um-title', style: { marginBottom: 10 } }, t('myInfo')),
          h('dl', { className: 'um-kv' },
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
              ? h('div', { className: 'um-muted' }, t('empty'))
              : h('table', { className: 'um-table' },
                h('thead', null, h('tr', null,
                  h('th', null, t('colTime')),
                  h('th', null, t('colType')),
                  h('th', null, t('colIp')))),
                h('tbody', null, entries.map((entry, i) => h('tr', { key: i },
                  h('td', { className: 'um-muted', style: { whiteSpace: 'nowrap' } }, formatTime(entry.ts)),
                  h('td', null, t(TYPE_LABELS[entry.type] || entry.type)),
                  h('td', { className: 'um-muted' }, entry.ip || '-')))))))
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
        api('/session').then((d) => setMe(d.user)).catch(() => setMe(null))
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
      const tabs = [['users', t('tabUsers')], ['loginLog', t('tabLoginLog')], ['accessLog', t('tabAccessLog')], ['auditLog', t('tabAuditLog')]]
      return h('div', { style: { display: 'flex', flexDirection: 'column', gap: 12 } },
        h('div', { className: 'um-tabs' }, tabs.map(([key, label]) =>
          h('button', { key, className: tab === key ? 'um-tab active' : 'um-tab', onClick: () => setTab(key) }, label))),
        tab === 'users' ? h(UsersTab, { me, __t: t, flash })
          : tab === 'auditLog' ? h(AuditTab, { __t: t })
            : h(ActivityTab, { kind: tab, __t: t }))
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
      __internals: { NS, ZH, EN, TYPE_LABELS, api, formatTime, interpolate, filterActivity, filterAudit },
      apply(ctx) {
        ctx.locale.register(NS, 'zh', ZH)
        ctx.locale.register(NS, 'en', EN)
        const t = ctx.locale.bind(NS)
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

    return module.exports
  }
})
